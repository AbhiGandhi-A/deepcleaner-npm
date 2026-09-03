export class DeepCleanerError extends Error {
  constructor(message: string, public readonly code: string = 'DC_ERROR') {
    super(message);
    this.name = 'DeepCleanerError';
  }
}

export class ScannerError extends DeepCleanerError {
  constructor(public readonly scannerId: string, message: string, public readonly originalError?: unknown) {
    super(`Scanner '${scannerId}' failed: ${message}`, 'DC_SCANNER_ERROR');
    this.name = 'ScannerError';
  }
}

export class SafetyLimitError extends DeepCleanerError {
  constructor(message: string) {
    super(`Safety limit exceeded: ${message}`, 'DC_SAFETY_LIMIT_ERROR');
    this.name = 'SafetyLimitError';
  }
}

export class ConfigurationError extends DeepCleanerError {
  constructor(message: string) {
    super(`Configuration error: ${message}`, 'DC_CONFIG_ERROR');
    this.name = 'ConfigurationError';
  }
}
