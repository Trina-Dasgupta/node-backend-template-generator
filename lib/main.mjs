import inquirer from 'inquirer';
import chalk from 'chalk';
import path from 'path';
import { MonolithicGenerator } from './generators/monolithicGenerator.mjs';
import { fileExists } from './utils/fileUtils.mjs';

export async function main() {
  console.log(chalk.blue.bold('\n🚀 Node.js Backend Generator'));
  console.log(chalk.gray('Creating a professional Node.js backend template...\n'));

  try {
    // Welcome message with feature highlights
    console.log(chalk.cyan('✨ Available Features:'));
    console.log(chalk.gray('• Multiple database support (MongoDB, MySQL, PostgreSQL)'));
    console.log(chalk.gray('• JWT Authentication with refresh tokens'));
    console.log(chalk.gray('• File upload with Multer'));
    console.log(chalk.gray('• Email service with templates'));
    console.log(chalk.gray('• API documentation with Swagger'));
    console.log(chalk.gray('• Docker containerization'));
    console.log(chalk.gray('• Rate limiting & input validation'));
    console.log(chalk.gray('• Security best practices\n'));

    const answers = await inquirer.prompt([
      {
        type: 'input',
        name: 'projectName',
        message: 'Enter your project name:',
        default: 'my-backend',
        validate: (input) => {
          const projectName = input.trim();
          
          if (!projectName) {
            return 'Project name cannot be empty!';
          }
          
          if (projectName.includes(' ')) {
            return 'Project name cannot contain spaces!';
          }
          
          if (!/^[a-zA-Z][a-zA-Z0-9_-]*$/.test(projectName)) {
            return 'Project name must start with a letter and can only contain letters, numbers, hyphens, and underscores!';
          }
          
          if (projectName.length > 50) {
            return 'Project name cannot exceed 50 characters!';
          }
          
          return true;
        },
        filter: (input) => input.trim()
      },
      {
        type: 'list',
        name: 'moduleType',
        message: 'Choose module system:',
        choices: [
          { 
            name: 'ES Modules (MJS) - Modern JavaScript', 
            value: 'mjs',
            description: 'Recommended for new projects'
          },
          { 
            name: 'CommonJS (CJS) - Traditional Node.js', 
            value: 'cjs',
            description: 'Compatible with most existing packages'
          }
        ],
        default: 'mjs'
      },
      {
        type: 'list',
        name: 'database',
        message: 'Choose database ORM:',
        choices: [
          { 
            name: 'Mongoose (MongoDB)', 
            value: 'mongoose',
            description: 'Document database - Flexible schema'
          },
          { 
            name: 'Sequelize (MySQL/PostgreSQL)', 
            value: 'sequelize',
            description: 'SQL database - Structured data'
          },
          { 
            name: 'Prisma (Multi-database)', 
            value: 'prisma',
            description: 'Modern ORM - Type-safe database access'
          },
          { 
            name: 'None (API only)', 
            value: 'none',
            description: 'No database - REST API only'
          }
        ],
        default: 'mongoose'
      },
      {
        type: 'checkbox',
        name: 'features',
        message: 'Select additional features:',
        pageSize: 10,
        choices: [
          { 
            name: '🔐 Authentication (JWT + Refresh Tokens)', 
            value: 'auth',
            checked: true,
            description: 'User registration, login, JWT tokens'
          },
          { 
            name: '📁 File Upload (Multer)', 
            value: 'fileUpload',
            checked: false,
            description: 'Single & multiple file upload with validation'
          },
          { 
            name: '📧 Email Service (Nodemailer)', 
            value: 'email',
            checked: false,
            description: 'Welcome emails, password reset, notifications'
          },
          { 
            name: '📚 API Documentation (Swagger)', 
            value: 'docs',
            checked: true,
            description: 'Auto-generated API docs with Swagger UI'
          },
          { 
            name: '🐳 Docker Support', 
            value: 'docker',
            checked: false,
            description: 'Dockerfile & docker-compose setup'
          },
          { 
            name: '🛡️ Rate Limiting', 
            value: 'rateLimit',
            checked: true,
            description: 'Protect against brute force attacks'
          },
          { 
            name: '✅ Input Validation (Joi)', 
            value: 'validation',
            checked: true,
            description: 'Request validation middleware'
          },
          { 
            name: '🧪 Testing Setup (Jest)', 
            value: 'testing',
            checked: false,
            description: 'Test configuration with examples'
          }
        ],
        validate: (answer) => {
          if (answer.includes('auth') && answer.includes('none')) {
            return 'Authentication requires a database. Please select a database ORM or remove authentication.';
          }
          return true;
        }
      },
      {
        type: 'confirm',
        name: 'includeGit',
        message: 'Initialize Git repository?',
        default: true,
        when: (answers) => !fileExists(path.join(answers.projectName, '.git'))
      },
      {
        type: 'confirm',
        name: 'installDeps',
        message: 'Install dependencies automatically?',
        default: true
      }
    ]);

    // Validate feature combinations
    if (answers.features.includes('auth') && answers.database === 'none') {
      console.log(chalk.yellow('\n⚠️  Warning: Authentication requires a database.'));
      const { proceed } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'proceed',
          message: 'Continue without authentication?',
          default: false
        }
      ]);
      
      if (!proceed) {
        console.log(chalk.yellow('Operation cancelled.'));
        return;
      }
      
      // Remove auth from features
      answers.features = answers.features.filter(feature => feature !== 'auth');
    }

    // Check if directory already exists
    if (await fileExists(answers.projectName)) {
      const { overwrite } = await inquirer.prompt([
        {
          type: 'confirm',
          name: 'overwrite',
          message: `Directory "${answers.projectName}" already exists. Overwrite?`,
          default: false
        }
      ]);
      
      if (!overwrite) {
        console.log(chalk.yellow('Operation cancelled.'));
        return;
      }
    }

    // Show configuration summary
    console.log(chalk.cyan('\n📋 Project Configuration:'));
    console.log(chalk.gray('─'.repeat(50)));
    console.log(chalk.white(`Project Name: ${chalk.green(answers.projectName)}`));
    console.log(chalk.white(`Module System: ${chalk.green(answers.moduleType.toUpperCase())}`));
    console.log(chalk.white(`Database: ${chalk.green(answers.database === 'none' ? 'None' : answers.database)}`));
    console.log(chalk.white(`Features: ${chalk.green(answers.features.length > 0 ? answers.features.join(', ') : 'None')}`));
    console.log(chalk.gray('─'.repeat(50)));

    const { confirm } = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'confirm',
        message: 'Proceed with this configuration?',
        default: true
      }
    ]);

    if (!confirm) {
      console.log(chalk.yellow('Operation cancelled.'));
      return;
    }

    console.log(chalk.blue('\n🛠️  Generating project structure...'));

    const generator = new MonolithicGenerator(answers);
    await generator.generate();
    
    console.log(chalk.green.bold('\n✅ Project generated successfully!'));
    
    // Enhanced next steps
    console.log(chalk.blue('\n🎯 Next Steps:'));
    console.log(chalk.white(`1. cd ${answers.projectName}`));
    
    if (answers.installDeps) {
      console.log(chalk.white('2. npm install (dependencies will be installed automatically)'));
    } else {
      console.log(chalk.white('2. npm install'));
    }
    
    if (answers.database !== 'none') {
      console.log(chalk.white('3. Update database configuration in .env file'));
    }
    
    if (answers.database === 'prisma') {
      console.log(chalk.white('4. npx prisma generate'));
      console.log(chalk.white('5. npx prisma db push'));
    }
    
    if (answers.features.includes('email')) {
      console.log(chalk.white('6. Configure SMTP settings in .env for email service'));
    }
    
    console.log(chalk.white('7. npm run dev (for development)'));
    console.log(chalk.white('8. npm start (for production)'));
    
    // Feature-specific tips
    if (answers.features.includes('docs')) {
      console.log(chalk.cyan('\n📚 API Documentation:'));
      console.log(chalk.white('Visit http://localhost:3000/api-docs after starting the server'));
    }
    
    if (answers.features.includes('auth')) {
      console.log(chalk.cyan('\n🔐 Authentication:'));
      console.log(chalk.white('• Register: POST /api/auth/register'));
      console.log(chalk.white('• Login: POST /api/auth/login'));
      console.log(chalk.white('• Profile: GET /api/auth/profile (requires auth)'));
    }
    
    if (answers.features.includes('docker')) {
      console.log(chalk.cyan('\n🐳 Docker:'));
      console.log(chalk.white('• docker-compose up -d (to start with database)'));
      console.log(chalk.white('• docker build -t your-app . (to build image)'));
    }

    console.log(chalk.green.bold('\n🚀 Happy coding! 🎉'));
    console.log(chalk.gray('\nNeed help? Check the README.md for detailed documentation.'));

  } catch (error) {
    if (error.message === 'User force closed the prompt') {
      console.log(chalk.yellow('\nOperation cancelled by user.'));
    } else {
      console.error(chalk.red('\n❌ Error generating project:'), error.message);
      console.log(chalk.gray('\nIf this issue persists, please check:'));
      console.log(chalk.gray('• Node.js version (requires 14.0.0+)'));
      console.log(chalk.gray('• Sufficient disk space and permissions'));
      console.log(chalk.gray('• Internet connection for package downloads'));
    }
    process.exit(1);
  }
}

