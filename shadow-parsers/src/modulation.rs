//! RF Modulation Quality Analyzer
//!
//! Analyzes I/Q samples for phase coherence, EVM (Error Vector Magnitude),
//! and SNR to detect spoofed/degraded signals.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModulationSample {
    pub phase_samples: Vec<f32>,      // I/Q phase sequence
    pub amplitude_samples: Vec<f32>,   // Signal magnitude
    pub sample_rate_hz: u32,
    pub center_frequency_hz: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModulationQuality {
    pub phase_coherence: f32,   // 0.0 = incoherent (spoofed), 1.0 = perfect
    pub evm_percent: f32,        // Error Vector Magnitude (lower = better)
    pub snr_db: f32,
    pub peak_amplitude: f32,
    pub mean_amplitude: f32,
}

#[derive(Debug, Clone, Copy)]
pub enum ModulationError {
    InsufficientSamples,
    InvalidSampleRate,
    InvalidFrequency,
}

pub fn analyze_modulation(sample: &ModulationSample) -> Result<ModulationQuality, ModulationError> {
    if sample.phase_samples.len() < 100 {
        return Err(ModulationError::InsufficientSamples);
    }

    if sample.sample_rate_hz == 0 {
        return Err(ModulationError::InvalidSampleRate);
    }

    // Calculate phase coherence (autocorrelation)
    let phase_coherence = calculate_phase_coherence(&sample.phase_samples);

    // Calculate EVM (Error Vector Magnitude)
    let evm_percent = calculate_evm(&sample.phase_samples);

    // Calculate SNR
    let snr_db = calculate_snr(&sample.amplitude_samples);

    // Calculate amplitude statistics
    let (peak_amplitude, mean_amplitude) = calculate_amplitude_stats(&sample.amplitude_samples);

    Ok(ModulationQuality {
        phase_coherence,
        evm_percent,
        snr_db,
        peak_amplitude,
        mean_amplitude,
    })
}

/// Calculate phase coherence via autocorrelation (Wiener-Khinchin)
fn calculate_phase_coherence(phases: &[f32]) -> f32 {
    if phases.len() < 2 {
        return 0.0;
    }

    let n = phases.len();
    let mean = phases.iter().sum::<f32>() / n as f32;

    let autocorr_0 = phases.iter().map(|p| (p - mean).powi(2)).sum::<f32>() / n as f32;
    let autocorr_1 = phases
        .windows(2)
        .map(|w| (w[0] - mean) * (w[1] - mean))
        .sum::<f32>()
        / (n - 1) as f32;

    if autocorr_0 > 0.0 {
        (autocorr_1 / autocorr_0).abs().min(1.0)
    } else {
        0.0
    }
}

/// Calculate EVM (Error Vector Magnitude) as percentage
fn calculate_evm(phases: &[f32]) -> f32 {
    if phases.len() < 2 {
        return 100.0;
    }

    // EVM is the ratio of error power to signal power
    let signal_power = phases.iter().map(|p| p.powi(2)).sum::<f32>() / phases.len() as f32;

    if signal_power < 0.001 {
        return 100.0;
    }

    // Estimate noise via variance of first differences
    let diffs: Vec<f32> = phases.windows(2).map(|w| w[1] - w[0]).collect();
    let noise_power = diffs.iter().map(|d| d.powi(2)).sum::<f32>() / diffs.len() as f32;

    let evm = (noise_power / signal_power).sqrt() * 100.0;
    evm.min(100.0)
}

/// Calculate SNR in dB
fn calculate_snr(amplitudes: &[f32]) -> f32 {
    if amplitudes.is_empty() {
        return 0.0;
    }

    let mean = amplitudes.iter().sum::<f32>() / amplitudes.len() as f32;
    let signal_power = mean.powi(2);

    let noise_variance = amplitudes
        .iter()
        .map(|a| (a - mean).powi(2))
        .sum::<f32>()
        / amplitudes.len() as f32;

    if noise_variance <= 0.0 {
        return 20.0; // Default for clean signal
    }

    let snr_linear = signal_power / noise_variance;
    10.0 * snr_linear.log10()
}

/// Calculate peak and mean amplitude
fn calculate_amplitude_stats(amplitudes: &[f32]) -> (f32, f32) {
    if amplitudes.is_empty() {
        return (0.0, 0.0);
    }

    let peak = amplitudes
        .iter()
        .copied()
        .fold(f32::NEG_INFINITY, f32::max);
    let mean = amplitudes.iter().sum::<f32>() / amplitudes.len() as f32;

    (peak, mean)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_modulation_analysis() {
        let mut sample = ModulationSample {
            phase_samples: (0..256).map(|i| (i as f32 * 0.01).sin()).collect(),
            amplitude_samples: (0..256).map(|_| 1.0).collect(),
            sample_rate_hz: 2_000_000,
            center_frequency_hz: 1090_000_000,
        };

        let result = analyze_modulation(&sample);
        assert!(result.is_ok());
        let quality = result.unwrap();
        assert!(quality.phase_coherence >= 0.0 && quality.phase_coherence <= 1.0);
        assert!(quality.evm_percent >= 0.0 && quality.evm_percent <= 100.0);
    }

    #[test]
    fn test_insufficient_samples() {
        let sample = ModulationSample {
            phase_samples: vec![1.0; 50],
            amplitude_samples: vec![1.0; 50],
            sample_rate_hz: 2_000_000,
            center_frequency_hz: 1090_000_000,
        };

        let result = analyze_modulation(&sample);
        assert!(matches!(result, Err(ModulationError::InsufficientSamples)));
    }
}
