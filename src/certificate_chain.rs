use crate::crypto::{Certificate, Verifier};
use crate::kds::KdsFetcher;
use crate::{snp, AttestationReport};
use log::info;
use std::collections::HashMap;
use std::mem::discriminant;

pub struct Chain {
    /// AMD Root Key (ARK) certificate
    pub ark: Certificate,
    /// AMD SEV Key (ASK) certificate
    pub ask: Certificate,
}

/// AMD certificate chain representation for SEV-SNP verification
pub struct AmdCertificates {
    pub chains_cache: Vec<(snp::model::Generation, Chain)>,
    /// Versioned Chip Endorsement Key (VCEK) certificates by processor model
    vcek_cache: HashMap<String, Certificate>,
    /// Certificate fetcher
    fetcher: KdsFetcher,
}

impl AmdCertificates {
    /// Create a new AmdCertificates by fetching ARK and ASK from KDS
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_cache(false).await
    }

    /// Create a new AmdCertificates with caching enabled
    pub async fn with_cache(use_cache: bool) -> Result<Self, Box<dyn std::error::Error>> {
        // Create fetcher
        let fetcher = if use_cache {
            KdsFetcher::with_cache()
        } else {
            KdsFetcher::new()
        };

        Ok(Self {
            chains_cache: Vec::new(),
            vcek_cache: HashMap::new(),
            fetcher,
        })
    }

    async fn get_chain(
        &mut self,
        processor_model: snp::model::Generation,
    ) -> Result<&Chain, Box<dyn std::error::Error>> {
        let existing_indx = self
            .chains_cache
            .iter()
            .position(|(gen, _)| discriminant(gen) == discriminant(&processor_model));

        if let Some(indx) = existing_indx {
            return Ok(&self.chains_cache[indx].1);
        }

        let (ark, ask) = self
            .fetcher
            .fetch_amd_chain(processor_model)
            .await
            .map_err(|e| format!("Error fetching chain: {}", e))?;

        ark.verify(&ask)
            .map_err(|e| format!("Failed to verify ASK signature: {}", e))?;

        let chain = Chain { ark, ask };

        self.chains_cache.push((processor_model, chain));
        Ok(&self.chains_cache.last().unwrap().1)
    }

    /// Get or fetch the VCEK certificate for a given processor model and attestation report
    pub async fn get_vcek(
        &mut self,
        processor_model: snp::model::Generation,
        attestation_report: &AttestationReport,
    ) -> Result<&Certificate, Box<dyn std::error::Error>> {
        // Build cache key from processor model and chip_id
        let cache_key = format!(
            "{}_{:02x?}",
            processor_model,
            &attestation_report.chip_id[..8]
        );

        // Check if we already have this VCEK
        if !self.vcek_cache.contains_key(&cache_key) {
            // Fetch the VCEK
            let vcek = self
                .fetcher
                .fetch_amd_vcek(processor_model, attestation_report)
                .await?;

            // Verify that VCEK is signed by ASK
            let chain = self.get_chain(processor_model).await?;
            chain
                .ask
                .verify(&vcek)
                .map_err(|e| format!("Failed to verify VCEK signature: {}", e))?;

            info!(
                "VCEK certificate verified successfully for {}",
                processor_model
            );

            // Store in cache
            self.vcek_cache.insert(cache_key.clone(), vcek);
        }

        // Return reference to cached VCEK
        Ok(self.vcek_cache.get(&cache_key).unwrap())
    }

    /// Check if a VCEK is already cached for the given processor model
    pub fn has_vcek(&self, processor_model: &str, attestation_report: &AttestationReport) -> bool {
        let cache_key = format!(
            "{}_{:02x?}",
            processor_model,
            &attestation_report.chip_id[..8]
        );
        self.vcek_cache.contains_key(&cache_key)
    }
}

/// Trait for fetching AMD certificates from a certificate source
pub(crate) trait CertificateFetcher {
    /// Fetch AMD certificate chain (ARK and ASK)
    async fn fetch_amd_chain(
        &mut self,
        model: snp::model::Generation,
    ) -> Result<(Certificate, Certificate), Box<dyn std::error::Error>>;

    /// Fetch VCEK certificate for a given processor model and attestation report
    async fn fetch_amd_vcek(
        &mut self,
        model: snp::model::Generation,
        attestation_report: &AttestationReport,
    ) -> Result<Certificate, Box<dyn std::error::Error>>;
}
