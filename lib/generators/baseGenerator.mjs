import fs from 'fs-extra';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export class BaseGenerator {
  constructor(config) {
    this.config = config;
    this.projectPath = path.join(process.cwd(), config.projectName);
    this.templatePath = path.join(__dirname, '../templates');
  }

  async ensureDirectory(dir) {
    await fs.ensureDir(dir);
  }

  async copyTemplate(source, destination, variables = {}) {
    try {
      let content = await fs.readFile(source, 'utf8');
      
      // Replace template variables
      Object.keys(variables).forEach(key => {
        const regex = new RegExp(`{{${key}}}`, 'g');
        content = content.replace(regex, variables[key]);
      });

      await fs.writeFile(destination, content);
    } catch (error) {
      console.error(`Error copying template from ${source} to ${destination}:`, error);
      throw error;
    }
  }

  getPackageJson() {
    const isMJS = this.config.moduleType === 'mjs';
    const serverFile = isMJS ? 'server.mjs' : 'server.js';
    
    const basePackage = {
      name: this.config.projectName.toLowerCase().replace(/\s+/g, '-'),
      version: '1.0.0',
      description: 'Node.js backend application',
      type: isMJS ? 'module' : 'commonjs',
      main: serverFile,
      scripts: {
        start: `node ${serverFile}`,
        dev: 'nodemon server.js',
        test: 'jest'
      },
      keywords: ['nodejs', 'express', 'backend', 'api'],
      author: '',
      license: 'MIT',
      engines: {
        node: '>=14.0.0'
      }
    };

    // Core dependencies
    const dependencies = {
      'express': '^4.18.2',
      'cors': '^2.8.5',
      'helmet': '^7.0.0',
      'morgan': '^1.10.0',
      'dotenv': '^16.3.1',
      'compression': '^1.7.4' // Added for performance
    };

    // Database dependencies
    if (this.config.database === 'mongoose') {
      dependencies.mongoose = '^7.5.0';
    } else if (this.config.database === 'sequelize') {
      dependencies.sequelize = '^6.33.0';
      dependencies.mysql2 = '^3.6.0';
    } else if (this.config.database === 'prisma') {
      dependencies['@prisma/client'] = '^5.4.0';
    }

    // Feature dependencies
    if (this.config.features.includes('auth')) {
      dependencies.jsonwebtoken = '^9.0.2';
      dependencies.bcryptjs = '^2.4.3';
    }

    if (this.config.features.includes('fileUpload')) {
      dependencies.multer = '^1.4.5-lts.1';
    }

    if (this.config.features.includes('email')) {
      dependencies.nodemailer = '^6.9.4';
    }

    if (this.config.features.includes('docs')) {
      dependencies['swagger-jsdoc'] = '^6.2.8';
      dependencies['swagger-ui-express'] = '^5.0.0';
    }

    if (this.config.features.includes('rateLimit')) {
      dependencies['express-rate-limit'] = '^7.1.0';
    }

    if (this.config.features.includes('validation')) {
      dependencies.joi = '^17.11.0';
    }

    basePackage.dependencies = dependencies;

    // Dev dependencies
    const devDependencies = {
      'nodemon': '^3.0.1',
      'jest': '^29.6.4'
    };

    // Add Prisma dev dependency if selected
    if (this.config.database === 'prisma') {
      devDependencies.prisma = '^5.4.0';
    }

    basePackage.devDependencies = devDependencies;

    // Additional scripts
    if (this.config.database === 'prisma') {
      basePackage.scripts = {
        ...basePackage.scripts,
        'db:push': 'prisma db push',
        'db:generate': 'prisma generate',
        'db:studio': 'prisma studio',
        'db:migrate': 'prisma migrate dev'
      };
    }

    // Add linting and formatting scripts
    basePackage.scripts = {
      ...basePackage.scripts,
      'lint': 'eslint src/',
      'lint:fix': 'eslint src/ --fix'
    };

    return basePackage;
  }

  getEnvContent() {
    let env = `# Environment Configuration
NODE_ENV=development
PORT=3000
APP_NAME=${this.config.projectName}
`;

    // Database configurations
    if (this.config.database === 'mongoose') {
      env += `\n# MongoDB Configuration
MONGODB_URI=mongodb://localhost:27017/${this.config.projectName}
`;
    } else if (this.config.database === 'sequelize') {
      env += `\n# MySQL Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_NAME=${this.config.projectName}
DB_USER=root
DB_PASS=password
DB_DIALECT=mysql
`;
    } else if (this.config.database === 'prisma') {
      env += `\n# Prisma Database Configuration
DATABASE_URL="mysql://root:password@localhost:3306/${this.config.projectName}"
`;
    }

    // Authentication
    if (this.config.features.includes('auth')) {
      env += `\n# JWT Configuration
JWT_SECRET=your_super_secret_jwt_key_change_this_in_production
JWT_EXPIRES_IN=7d
JWT_REFRESH_SECRET=your_refresh_token_secret_change_this_too
JWT_REFRESH_EXPIRES_IN=30d
`;
    }

    // Email configuration
    if (this.config.features.includes('email')) {
      env += `\n# Email Configuration (SMTP)
SMTP_HOST=your_smtp_host
SMTP_PORT=587
SMTP_USER=your_smtp_username
SMTP_PASS=your_smtp_password
SMTP_FROM=noreply@${this.config.projectName.toLowerCase().replace(/\s+/g, '')}.com
CLIENT_URL=http://localhost:3000
`;
    }

    // File upload configuration
    if (this.config.features.includes('fileUpload')) {
      env += `\n# File Upload Configuration
MAX_FILE_SIZE=5242880
ALLOWED_FILE_TYPES=image/jpeg,image/png,image/gif,application/pdf
UPLOAD_PATH=./uploads
`;
    }

    // Rate limiting
    if (this.config.features.includes('rateLimit')) {
      env += `\n# Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
`;
    }

    // CORS configuration
    env += `\n# CORS Configuration
CORS_ORIGIN=http://localhost:3000
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
`;

    return env;
  }

  // Helper method to generate consistent file content
  generateFileContent(template, variables = {}) {
    let content = template;
    Object.keys(variables).forEach(key => {
      const regex = new RegExp(`{{${key}}}`, 'g');
      content = content.replace(regex, variables[key]);
    });
    return content;
  }

  // Method to validate project name
  validateProjectName(name) {
    if (!name || name.trim().length === 0) {
      throw new Error('Project name cannot be empty');
    }
    
    if (!/^[a-z0-9-]+$/.test(name.toLowerCase())) {
      throw new Error('Project name can only contain lowercase letters, numbers, and hyphens');
    }
    
    if (name.length > 50) {
      throw new Error('Project name cannot exceed 50 characters');
    }
    
    return true;
  }

  // Method to get database-specific configuration
  getDatabaseConfig() {
    const config = {
      mongoose: {
        package: 'mongoose',
        version: '^7.5.0'
      },
      sequelize: {
        package: 'sequelize',
        version: '^6.33.0',
        additional: ['mysql2@^3.6.0']
      },
      prisma: {
        package: '@prisma/client',
        version: '^5.4.0'
      }
    };
    
    return config[this.config.database] || {};
  }

  // Method to get feature-specific dependencies
  getFeatureDependencies() {
    const featureDeps = {
      auth: [
        { name: 'jsonwebtoken', version: '^9.0.2' },
        { name: 'bcryptjs', version: '^2.4.3' }
      ],
      fileUpload: [
        { name: 'multer', version: '^1.4.5-lts.1' }
      ],
      email: [
        { name: 'nodemailer', version: '^6.9.4' }
      ],
      docs: [
        { name: 'swagger-jsdoc', version: '^6.2.8' },
        { name: 'swagger-ui-express', version: '^5.0.0' }
      ],
      rateLimit: [
        { name: 'express-rate-limit', version: '^7.1.0' }
      ],
      validation: [
        { name: 'joi', version: '^17.11.0' }
      ]
    };

    const dependencies = {};
    this.config.features.forEach(feature => {
      if (featureDeps[feature]) {
        featureDeps[feature].forEach(dep => {
          dependencies[dep.name] = dep.version;
        });
      }
    });

    return dependencies;
  }

  // Add to BaseGenerator class
getMicroserviceDependencies() {
  const microserviceDeps = {
    bullmq: [
      { name: 'bullmq', version: '^4.0.0' },
      { name: 'ioredis', version: '^5.3.0' }
    ],
    rabbitmq: [
      { name: 'amqplib', version: '^0.10.0' }
    ],
    kafka: [
      { name: 'kafkajs', version: '^2.2.0' }
    ],
    apiGateway: [
      { name: 'http-proxy-middleware', version: '^2.0.0' },
      { name: 'express-http-proxy', version: '^2.0.0' }
    ],
    serviceDiscovery: [
      { name: 'consul', version: '^0.40.0' }
    ]
  };

  const dependencies = {};
  
  if (this.config.architecture === 'microservices') {
    this.config.microservices.messageQueue.forEach(queue => {
      if (microserviceDeps[queue]) {
        microserviceDeps[queue].forEach(dep => {
          dependencies[dep.name] = dep.version;
        });
      }
    });

    if (this.config.microservices.includeApiGateway) {
      microserviceDeps.apiGateway.forEach(dep => {
        dependencies[dep.name] = dep.version;
      });
    }

    if (this.config.microservices.includeServiceDiscovery) {
      microserviceDeps.serviceDiscovery.forEach(dep => {
        dependencies[dep.name] = dep.version;
      });
    }
  }

  return dependencies;
}
}