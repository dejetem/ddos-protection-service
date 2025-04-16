# DDoS Protection Service

A comprehensive DDoS protection and traffic management system for web applications, built with Rust and Cloudflare technologies.

## Project Overview

This service provides robust DDoS protection and traffic management capabilities for web applications by leveraging Cloudflare's infrastructure and custom logic implemented in Rust. The system is designed to be scalable, efficient, and easy to integrate with existing web applications.

## Features

- Real-time DDoS attack detection and mitigation
- Rate limiting with Redis-based storage
- Traffic analysis and monitoring
- Custom rule configuration
- API for integration with existing systems
- Comprehensive logging and analytics
- Docker containerization for easy deployment

## Tech Stack

- **Backend**: Rust
- **Infrastructure**: Cloudflare Workers
- **DDoS Protection**: Cloudflare DDoS Protection
- **Rate Limiting**: Redis
- **Containerization**: Docker
- **Monitoring**: Cloudflare Analytics
- **Testing**: Rust's built-in testing framework, integration tests

## Project Structure

- **src/**: Contains the main source code
   - **main.rs**: Application entry point
   - **api/**: HTTP endpoints
   - **core/**: Core business logic
   - **config/**: Configuration management
- **config/**: Configuration files
- **docker/**: Docker-related files
- **tests/**: Test suites


## Getting Started

### Prerequisites

- Rust (latest stable version)
- Docker
- Redis
- Cloudflare account with Workers enabled

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/ddos-protection-service.git
   cd ddos-protection-service
   ```

2. Install dependencies:
   ```bash
   cargo build
   ```

3. Configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. Run the service:
   ```bash
   cargo run
   ```

### Running with Docker

The project includes Docker configuration for easy deployment. Here's how to run it:

1. Build and start the containers:
   ```bash
   docker-compose up --build
   ```
   This will:
   - Build the Rust application container
   - Start a Redis container
   - Set up the network between containers
   - Mount the necessary volumes

2. For development with hot-reloading:
   ```bash
   docker-compose -f docker-compose.yml -f docker-compose.dev.yml up
   ```

3. To run in detached mode:
   ```bash
   docker-compose up -d
   ```

4. To stop the services:
   ```bash
   docker-compose down
   ```

5. To view logs:
   ```bash
   docker-compose logs -f
   ```

### Environment Variables for Docker

When running with Docker, you can set environment variables in several ways:

1. Using a `.env` file (recommended for development):
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

2. Using docker-compose environment section:
   ```yaml
   services:
     app:
       environment:
         - RUST_LOG=info
         - REDIS_URL=redis://redis:6379
         - CLOUDFLARE_API_TOKEN=your_token_here
   ```

3. Using command line:
   ```bash
   CLOUDFLARE_API_TOKEN=your_token_here docker-compose up
   ```

### Docker Configuration

The project includes:

- `docker/Dockerfile`: Multi-stage build for the Rust application
- `docker-compose.yml`: Main service configuration
- `docker-compose.dev.yml`: Development-specific overrides

The Docker setup includes:
- Multi-stage builds for smaller final image size
- Redis persistence through Docker volumes
- Network isolation between services
- Environment variable configuration
- Health checks for services

## Development Phases

1. **Phase 1**: Basic Infrastructure Setup
   - Project structure
   - Basic API endpoints
   - Configuration management

2. **Phase 2**: Core Protection Features
   - Rate limiting implementation
   - Basic DDoS detection
   - Redis integration

3. **Phase 3**: Advanced Features
   - Custom rule engine
   - Analytics integration
   - Advanced monitoring

4. **Phase 4**: Testing and Documentation
   - Unit tests
   - Integration tests
   - API documentation
   - Deployment guides

## API Documentation

Detailed API documentation is available in the [docs/api.md](docs/api.md) file.

## Testing

Run the test suite:
```bash
cargo test
```

For running tests in Docker:
```bash
docker-compose run app cargo test
```

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Cloudflare for their excellent DDoS protection services
- The Rust community for their amazing ecosystem
- Contributors and maintainers 