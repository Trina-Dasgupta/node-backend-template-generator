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
    let content = await fs.readFile(source, 'utf8');
    
    // Replace template variables
    Object.keys(variables).forEach(key => {
      const regex = new RegExp(`{{${key}}}`, 'g');
      content = content.replace(regex, variables[key]);
    });

    await fs.writeFile(destination, content);
  }

  getPackageJson() {
    const basePackage = {
      name: this.config.projectName,
      version: '1.0.0',
      description: 'Node.js backend application',
      type: this.config.moduleType === 'mjs' ? 'module' : 'commonjs',
      main: this.config.moduleType === 'mjs' ? 'server.mjs' : 'server.js',
      scripts: {
        start: this.config.moduleType === 'mjs' ? 'node server.mjs' : 'node server.js',
        dev: 'nodemon server.js',
        test: 'jest'
      },
      keywords: ['nodejs', 'express', 'backend'],
      author: '',
      license: 'MIT'
    };

    // Add dependencies based on selections
    const dependencies = {
      'express': '^4.18.0',
      'cors': '^2.8.5',
      'helmet': '^5.0.0',
      'morgan': '^1.10.0',
      'dotenv': '^16.0.0'
    };

    // Database dependencies
    if (this.config.database === 'mongoose') {
      dependencies.mongoose = '^6.0.0';
    } else if (this.config.database === 'sequelize') {
      dependencies.sequelize = '^6.0.0';
      dependencies.mysql2 = '^2.3.0';
    } else if (this.config.database === 'prisma') {
      dependencies['@prisma/client'] = '^4.0.0';
    }

    // Feature dependencies
    if (this.config.features.includes('auth')) {
      dependencies.jsonwebtoken = '^8.5.1';
      dependencies.bcryptjs = '^2.4.3';
    }

    if (this.config.features.includes('fileUpload')) {
      dependencies.multer = '^1.4.4';
    }

    if (this.config.features.includes('email')) {
      dependencies.nodemailer = '^6.7.0';
    }

    basePackage.dependencies = dependencies;

    // Dev dependencies
    basePackage.devDependencies = {
      'nodemon': '^2.0.0',
      'jest': '^28.0.0'
    };

    if (this.config.database === 'prisma') {
      basePackage.devDependencies.prisma = '^4.0.0';
      basePackage.scripts['db:push'] = 'prisma db push';
      basePackage.scripts['db:generate'] = 'prisma generate';
    }

    return basePackage;
  }

  getEnvContent() {
    let env = `NODE_ENV=development
PORT=3000
`;

    if (this.config.database === 'mongoose') {
      env += `MONGODB_URI=mongodb://localhost:27017/${this.config.projectName}\n`;
    } else if (this.config.database === 'sequelize') {
      env += `DB_HOST=localhost
DB_PORT=3306
DB_NAME=${this.config.projectName}
DB_USER=root
DB_PASS=password\n`;
    }

    if (this.config.features.includes('auth')) {
      env += `JWT_SECRET=your_jwt_secret_key_here
JWT_EXPIRES_IN=7d\n`;
    }

    if (this.config.features.includes('email')) {
      env += `SMTP_HOST=your_smtp_host
SMTP_PORT=587
SMTP_USER=your_smtp_user
SMTP_PASS=your_smtp_password\n`;
    }

    return env;
  }
}