use crate::config::schema::GatewayConfig;
use crate::config::ApplyStrategy;
use crate::diff::resource_diff::{compute_diff, DiffAction};
use crate::http_client::AdminClient;

#[derive(Debug, Default)]
pub struct ApplyResult {
    pub created: usize,
    pub updated: usize,
    pub deleted: usize,
    pub errors: Vec<String>,
}

pub async fn apply_api(
    desired: &GatewayConfig,
    client: &AdminClient,
    strategy: ApplyStrategy,
    namespace_filter: Option<&str>,
) -> crate::error::Result<ApplyResult> {
    let namespace = namespace_filter.unwrap_or("ferrum");

    match strategy {
        ApplyStrategy::FullReplace => {
            client.post_restore(desired, namespace).await?;
            Ok(ApplyResult {
                created: desired.proxies.len()
                    + desired.consumers.len()
                    + desired.upstreams.len()
                    + desired.plugin_configs.len(),
                ..Default::default()
            })
        }
        ApplyStrategy::Incremental => apply_incremental(desired, client, namespace).await,
    }
}

async fn apply_incremental(
    desired: &GatewayConfig,
    client: &AdminClient,
    namespace: &str,
) -> crate::error::Result<ApplyResult> {
    let actual = client.get_backup(namespace).await?;
    let diffs = compute_diff(desired, &actual);

    let mut result = ApplyResult::default();

    for diff in &diffs {
        let outcome = match (&diff.action, diff.kind.as_str()) {
            (DiffAction::Add, "Proxy") => {
                let proxy = desired.proxies.iter().find(|p| p.id == diff.id);
                match proxy {
                    Some(p) => client.create_proxy(p, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Modify, "Proxy") => {
                let proxy = desired.proxies.iter().find(|p| p.id == diff.id);
                match proxy {
                    Some(p) => client.update_proxy(p, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Delete, "Proxy") => client.delete_proxy(&diff.id, namespace).await,

            (DiffAction::Add, "Consumer") => {
                let consumer = desired.consumers.iter().find(|c| c.id == diff.id);
                match consumer {
                    Some(c) => client.create_consumer(c, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Modify, "Consumer") => {
                let consumer = desired.consumers.iter().find(|c| c.id == diff.id);
                match consumer {
                    Some(c) => client.update_consumer(c, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Delete, "Consumer") => client.delete_consumer(&diff.id, namespace).await,

            (DiffAction::Add, "Upstream") => {
                let upstream = desired.upstreams.iter().find(|u| u.id == diff.id);
                match upstream {
                    Some(u) => client.create_upstream(u, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Modify, "Upstream") => {
                let upstream = desired.upstreams.iter().find(|u| u.id == diff.id);
                match upstream {
                    Some(u) => client.update_upstream(u, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Delete, "Upstream") => client.delete_upstream(&diff.id, namespace).await,

            (DiffAction::Add, "PluginConfig") => {
                let pc = desired.plugin_configs.iter().find(|p| p.id == diff.id);
                match pc {
                    Some(p) => client.create_plugin_config(p, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Modify, "PluginConfig") => {
                let pc = desired.plugin_configs.iter().find(|p| p.id == diff.id);
                match pc {
                    Some(p) => client.update_plugin_config(p, namespace).await,
                    None => continue,
                }
            }
            (DiffAction::Delete, "PluginConfig") => {
                client.delete_plugin_config(&diff.id, namespace).await
            }

            _ => continue,
        };

        match outcome {
            Ok(()) => match diff.action {
                DiffAction::Add => result.created += 1,
                DiffAction::Modify => result.updated += 1,
                DiffAction::Delete => result.deleted += 1,
            },
            Err(e) => {
                result.errors.push(format!(
                    "{} {} {}: {}",
                    diff.kind,
                    diff.id,
                    match diff.action {
                        DiffAction::Add => "create",
                        DiffAction::Modify => "update",
                        DiffAction::Delete => "delete",
                    },
                    e
                ));
            }
        }
    }

    Ok(result)
}
