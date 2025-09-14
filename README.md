# Threat Modeler: Definitive Edition

A comprehensive threat modeling tool that combines PASTA (Process for Attack Simulation and Threat Analysis) and STRIDE methodologies with AI-powered analysis using local Ollama models and Google Gemini Pro enrichment.

## 🚀 Features

- **Dual Methodology Support**: Implements both PASTA and STRIDE threat modeling frameworks
- **AI-Powered Analysis**: Uses local Ollama models for private threat analysis and Google Gemini Pro for enrichment
- **Comprehensive Risk Assessment**: Includes OWASP, MITRE ATT&CK, and NIST framework mappings
- **Visual Threat Modeling**: Generates graphviz-based threat model diagrams
- **PDF Report Generation**: Creates detailed threat assessment reports
- **Attack Chain Analysis**: Models potential attack sequences and vectors
- **Real-time Threat Intelligence**: Integrates current threat landscape information

## 📋 Prerequisites

- Python 3.7 or higher
- Google Cloud Platform account (for Gemini Pro API access)
- Ollama installation (for local AI models)
- Graphviz installation (for diagram generation)

## 🛠️ Installation

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/Threat-Modelling.git
cd Threat-Modelling
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Install Graphviz
- **macOS**: `brew install graphviz`
- **Ubuntu/Debian**: `sudo apt-get install graphviz`
- **Windows**: Download from [Graphviz website](https://graphviz.org/download/)

### 4. Install and Configure Ollama
```bash
# Install Ollama (visit https://ollama.ai for platform-specific instructions)
ollama pull llama2  # or your preferred model
```

### 5. Configure Google Cloud credentials
```bash
# Set up Google Cloud credentials for Gemini Pro
export GOOGLE_APPLICATION_CREDENTIALS="path/to/your/credentials.json"
```

## 🚀 Usage

### Basic Usage
```bash
python threat_modelling.py
```

The application will guide you through an interactive threat modeling session:

1. **System Definition**: Define your system architecture and components
2. **Asset Identification**: Catalog data flows and trust boundaries
3. **Threat Analysis**: AI-powered identification of potential threats
4. **Risk Assessment**: Evaluate and prioritize identified threats
5. **Mitigation Planning**: Generate recommendations for threat mitigation
6. **Report Generation**: Create comprehensive PDF reports and visual diagrams

### Advanced Features

#### Custom Configuration
The tool supports YAML-based configuration for:
- System architectures
- Custom threat scenarios
- Risk assessment criteria
- Compliance frameworks

#### API Integration
Integrates with various security APIs for:
- Current vulnerability databases
- Threat intelligence feeds
- Compliance framework updates

## 📊 Output Formats

- **PDF Reports**: Comprehensive threat assessment documents
- **JSON Data**: Machine-readable threat model exports
- **Graphviz Diagrams**: Visual threat model representations
- **YAML Configs**: Reusable threat model configurations

## 🔧 Configuration

### Environment Variables
```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/credentials.json"
export OLLAMA_HOST="localhost:11434"  # Default Ollama endpoint
```

### Supported AI Models
- **Local Models**: Any Ollama-compatible model (Llama2, CodeLlama, Mistral, etc.)
- **Cloud Models**: Google Gemini Pro (via Vertex AI)

## 🧪 Testing

```bash
# Run basic functionality test
python -c "import threat_modelling; print('Installation successful')"
```

## 📖 Methodology

### PASTA Framework
Process for Attack Simulation and Threat Analysis:
1. Define Objectives
2. Define Technical Scope
3. Application Decomposition
4. Threat Analysis
5. Weakness & Vulnerability Analysis
6. Attack Modeling
7. Risk & Impact Analysis

### STRIDE Framework
Threat categorization model:
- **Spoofing**: Identity verification threats
- **Tampering**: Data integrity threats
- **Repudiation**: Non-repudiation threats
- **Information Disclosure**: Confidentiality threats
- **Denial of Service**: Availability threats
- **Elevation of Privilege**: Authorization threats

## 🛡️ Security Frameworks Integration

- **OWASP Top 10**: Web application security risks
- **MITRE ATT&CK**: Tactics, techniques, and procedures
- **NIST Cybersecurity Framework**: Risk management controls
- **ISO 27001**: Information security management

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-feature`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin feature/new-feature`)
5. Create a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: Report bugs and feature requests via [GitHub Issues](https://github.com/yourusername/Threat-Modelling/issues)
- **Documentation**: Comprehensive guides available in the `docs/` directory
- **Community**: Join our discussions in the project's GitHub Discussions

## 🔄 Version History

- **v1.0.0**: Initial release with PASTA/STRIDE integration
- **Future**: Planned features include OCTAVE, FAIR, and additional AI model support

## ⚠️ Disclaimer

This tool is designed for defensive security analysis and threat modeling purposes. Users are responsible for ensuring compliance with their organization's security policies and applicable regulations.

## 🙏 Acknowledgments

- PASTA methodology by Risk Centric Security
- STRIDE framework by Microsoft
- OWASP Foundation for security guidelines
- MITRE Corporation for ATT&CK framework
- NIST for cybersecurity framework guidance
