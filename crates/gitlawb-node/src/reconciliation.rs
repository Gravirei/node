use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::watch;

use crate::config::Config;
use crate::db::Db;

/// How often to run a sweep pass.
const SWEEP_INTERVAL_SECS: u64 = 3600;

/// Maximum repos to process per pass — prevents the sweep from becoming
/// the O(repos) amplification the admission-control work exists to prevent.
const REPOS_PER_PASS: usize = 100;

/// Maximum objects to pin per repo in a single pass — prevents one large
/// repo from monopolizing the blocking pool or the hourly budget.
const MAX_OBJECTS_PER_REPO: usize = 50_000;

/// Spawn the periodic reconciliation sweep background task.
pub fn spawn(
    db: Arc<Db>,
    config: Arc<Config>,
    http_client: Arc<reqwest::Client>,
    node_keypair: Arc<gitlawb_core::identity::Keypair>,
    node_did: gitlawb_core::did::Did,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let node_seed = *node_keypair.to_seed();
        let mut cursor = 0usize;

        // Run the first pass immediately on startup, then periodically.
        loop {
            let start = std::time::Instant::now();
            match run_pass(
                &db,
                &config,
                &http_client,
                &node_seed,
                &node_did,
                &mut cursor,
            )
            .await
            {
                Ok((count, gaps, filled)) => {
                    tracing::info!(
                        repos = count,
                        gaps_found = gaps,
                        gaps_filled = filled,
                        elapsed_ms = start.elapsed().as_millis() as u64,
                        "reconciliation sweep pass complete"
                    );
                }
                Err(e) => {
                    tracing::warn!(err = %e, "reconciliation sweep pass failed");
                }
            }

            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(SWEEP_INTERVAL_SECS)) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        tracing::info!("reconciliation sweep: shutdown signal received, exiting");
                        return;
                    }
                }
            }
        }
    });
}

/// Run one sweep pass. Returns `(repos_scanned, gaps_found, gaps_filled)`.
async fn run_pass(
    db: &Db,
    config: &Config,
    http_client: &reqwest::Client,
    node_seed: &[u8; 32],
    node_did: &gitlawb_core::did::Did,
    cursor: &mut usize,
) -> anyhow::Result<(usize, usize, usize)> {
    // Use the canonical/deduplicated listing so mirror rows never bypass
    // visibility rules. The dedup CTE also excludes quarantined repos.
    let all = db.list_all_repos_deduped().await?;

    if all.is_empty() {
        *cursor = 0;
        return Ok((0, 0, 0));
    }

    // Clamp the cursor so a shrinking eligible set never panics.
    let start = (*cursor).min(all.len());
    let end = (start + REPOS_PER_PASS).min(all.len());
    let batch = &all[start..end];
    *cursor = if end >= all.len() { 0 } else { end };

    let mut total_gaps_found = 0usize;
    let mut total_gaps_filled = 0usize;

    for repo in batch {
        let repo_slug = format!(
            "{}/{}",
            crate::db::normalize_owner_key(&repo.owner_did),
            repo.name
        );

        let disk = PathBuf::from(&repo.disk_path);
        if !disk.exists() {
            tracing::warn!(repo = %repo_slug, "disk path missing, skipping");
            continue;
        }

        let rules = match db.list_visibility_rules(&repo.id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "visibility rules fetch failed, skipping");
                continue;
            }
        };

        if !crate::visibility::listable_at_root(&rules, repo.is_public, &repo.owner_did, None) {
            continue;
        }

        let disk_clone = disk.clone();
        let owner_clone = repo.owner_did.clone();
        let rules_clone = rules.clone();
        let is_public = repo.is_public;
        let object_list = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
            let all_objs = crate::git::push_delta::list_all_objects(&disk_clone)?;
            // Always compute the reachable, visibility-allowed blob set so
            // ordinary public repos recover their blobs too (not just commits
            // and trees). replicable_blob_set handles the no-rule case
            // correctly — all reachable blobs are allowed.
            let allowed = crate::git::visibility_pack::replicable_blob_set(
                &disk_clone,
                &rules_clone,
                is_public,
                &owner_clone,
            )?;
            let all_blobs = crate::git::push_delta::all_blob_oids(&disk_clone)?;
            Ok(crate::git::visibility_pack::replicable_objects_fail_closed(
                all_objs, &allowed, &all_blobs,
            ))
        })
        .await;

        let mut object_list = match object_list {
            Ok(Ok(list)) => list,
            Ok(Err(e)) => {
                tracing::warn!(repo = %repo_slug, err = %e, "full-scan failed, skipping");
                continue;
            }
            Err(e) => {
                tracing::warn!(repo = %repo_slug, err = %e, "full-scan task panicked, skipping");
                continue;
            }
        };

        if object_list.is_empty() {
            continue;
        }

        // Enforce per-repo object cap so a huge repo cannot monopolize the
        // blocking pool or run past the hourly interval.
        let truncated = object_list.len() > MAX_OBJECTS_PER_REPO;
        if truncated {
            object_list.truncate(MAX_OBJECTS_PER_REPO);
            tracing::warn!(
                repo = %repo_slug,
                cap = MAX_OBJECTS_PER_REPO,
                "reconciliation per-repo object cap reached, truncating"
            );
        }

        let has_path_scoped = crate::git::visibility_pack::has_path_scoped_rule(&rules);

        // ── Phase 1: Public-object pinning (IPFS + Pinata) ────────────────
        // Each backend independently tracks its own completion state, so we
        // pass the full replicable set to both.  A row in pinned_cids from
        // IPFS does not imply a Pinata upload succeeded, and vice versa.
        let pinned_ipfs =
            crate::ipfs_pin::pin_new_objects(&config.ipfs_api, &disk, object_list.clone(), db)
                .await;

        let pinned_pinata = crate::pinata::pin_new_objects(
            http_client,
            &config.pinata_upload_url,
            &config.pinata_jwt,
            &disk,
            object_list,
            db,
        )
        .await;

        let repo_filled = pinned_ipfs.len() + pinned_pinata.len();
        if repo_filled > 0 {
            total_gaps_filled += repo_filled;
            // Approximate gaps count for observability — objects that were
            // missing from at least one backend.
            let missing_ipfs = pinned_ipfs.len();
            let missing_pinata = pinned_pinata.len();
            let deduped = pinned_ipfs
                .iter()
                .chain(&pinned_pinata)
                .collect::<HashSet<_>>()
                .len();
            total_gaps_found += deduped;
            crate::metrics::record_reconciliation_gaps_found(deduped as u64);
            crate::metrics::record_reconciliation_gaps_filled(repo_filled as u64);

            tracing::info!(
                repo = %repo_slug,
                ipfs = missing_ipfs,
                pinata = missing_pinata,
                total = repo_filled,
                "reconciliation sweep filled public-object gaps"
            );
        }

        // ── Phase 2: Encrypted recovery-copy resealing (withheld blobs) ──
        // Only relevant when path-scoped visibility rules exist — without them
        // no blobs are withheld and withheld_blob_recipients returns empty.
        if has_path_scoped && !config.ipfs_api.is_empty() {
            let p = disk.clone();
            let owner = repo.owner_did.clone();
            let r = rules.clone();
            let is_public_2 = repo.is_public;
            let recipients = tokio::task::spawn_blocking(move || {
                crate::git::visibility_pack::withheld_blob_recipients(&p, &r, is_public_2, &owner)
            })
            .await;

            match recipients {
                Ok(Ok(rec)) if !rec.is_empty() => {
                    let sealed = crate::encrypted_pin::encrypt_and_pin(
                        &config.ipfs_api,
                        &disk,
                        db,
                        &repo.id,
                        node_seed,
                        &rec,
                    )
                    .await;
                    if !sealed.is_empty() && !config.irys_url.is_empty() {
                        let owner_short = crate::db::normalize_owner_key(&repo.owner_did);
                        let slug = format!("{}/{}", owner_short, repo.name);
                        let ts = chrono::Utc::now().to_rfc3339();
                        let node_did_str = node_did.to_string();
                        let blobs: Vec<(String, String)> = sealed;
                        let manifest = crate::arweave::EncryptedManifest {
                            repo: &slug,
                            owner_did: &repo.owner_did,
                            node_did: &node_did_str,
                            timestamp: &ts,
                            blobs: &blobs,
                        };
                        if let Err(e) = crate::arweave::anchor_encrypted_manifest(
                            http_client,
                            &config.irys_url,
                            &manifest,
                        )
                        .await
                        {
                            tracing::warn!(
                                repo = %slug,
                                err = %e,
                                "encrypted manifest anchor failed (best-effort)"
                            );
                        }
                    }
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    tracing::warn!(
                        repo = %repo_slug,
                        err = %e,
                        "withheld_blob_recipients failed, skipping encrypted pin"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        repo = %repo_slug,
                        err = %e,
                        "withheld_blob_recipients task panicked, skipping encrypted pin"
                    );
                }
            }
        }
    }

    Ok((batch.len(), total_gaps_found, total_gaps_filled))
}
