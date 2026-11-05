output "beacon_private_ip" {
  description = "Endpoint the validator client dials."
  value       = module.validator.beacon_private_ip
}

output "prometheus_scrape_targets" {
  description = "Paste these into the static_configs of monitoring/prometheus/scrape.yml."
  value       = module.validator.prometheus_scrape_targets
}

output "slashing_safety" {
  description = "Plan-time safety posture; keep this in the change record for the engagement."
  value       = module.validator.slashing_safety
}
