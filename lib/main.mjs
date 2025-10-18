import inquirer from 'inquirer';
import chalk from 'chalk';
import path from 'path';
import { MonolithicGenerator } from './generators/monolithicGenerator.mjs';
import { MicroserviceGenerator } from './generators/microserviceGenerator.mjs';
import { fileExists } from './utils/fileUtils.mjs';

export async function main() {
  console.log(chalk.blue.bold('\n🚀 Node.js Backend Generator'));
  console.log(chalk.gray('Creating a professional Node.js backend template...\n'));

  try {
    // Welcome message with architecture options
    console.log(chalk.cyan('🏗️  Available Architectures:'));
    console.log(chalk.gray('• Monolithic - Single application with all features'));
    console.log(chalk.gray('• Microservices - Distributed system with API Gateway'));
    console.log(chalk.gray('• Multiple database support (MongoDB, MySQL, PostgreSQL)'));
    console.log(chalk.gray('• Message queues (Redis, BullMQ) for microservices'));
    console.log(chalk.gray('• Docker containerization & orchestration\n'));

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
        name: 'architecture',
        message: 'Choose application architecture:',
        choices: [
          { 
            name: '🏛️  Monolithic - Single Application', 
            value: 'monolithic',
            description: 'All features in one codebase - Good for small to medium projects'
          },
          { 
            name: '🔗 Microservices - Distributed System', 
            value: 'microservices',
            description: 'Multiple services with API Gateway - Scalable for large projects'
          }
        ],
        default: 'monolithic'
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
      }
    ]);

    // Microservices-specific questions
    if (answers.architecture === 'microservices') {
      const microservicesAnswers = await inquirer.prompt([
        {
          type: 'checkbox',
          name: 'services',
          message: 'Select microservices to include:',
          pageSize: 10,
          choices: [
            { 
              name: '🔐 Auth Service', 
              value: 'auth',
              checked: true,
              description: 'Authentication & user management'
            },
            { 
              name: '👥 User Service', 
              value: 'user',
              checked: true,
              description: 'User profiles and management'
            },
            { 
              name: '📧 Notification Service', 
              value: 'notification',
              checked: true,
              description: 'Email, SMS, push notifications'
            },
            { 
              name: '📁 File Service', 
              value: 'file',
              checked: false,
              description: 'File upload and management'
            },
            { 
              name: '💰 Payment Service', 
              value: 'payment',
              checked: false,
              description: 'Payment processing (Stripe/Razorpay)'
            },
            { 
              name: '📊 Analytics Service', 
              value: 'analytics',
              checked: false,
              description: 'Data analytics and reporting'
            }
          ],
          validate: (answer) => {
            if (answer.length === 0) {
              return 'Please select at least one microservice';
            }
            return true;
          }
        },
        {
          type: 'checkbox',
          name: 'messageQueue',
          message: 'Select message queue system:',
          choices: [
            { 
              name: 'Redis + BullMQ', 
              value: 'bullmq',
              checked: true,
              description: 'Redis-based queue with BullMQ'
            },
            { 
              name: 'RabbitMQ', 
              value: 'rabbitmq',
              checked: false,
              description: 'Advanced Message Queuing Protocol'
            },
            { 
              name: 'Apache Kafka', 
              value: 'kafka',
              checked: false,
              description: 'Distributed event streaming platform'
            }
          ]
        },
        {
          type: 'confirm',
          name: 'includeApiGateway',
          message: 'Include API Gateway?',
          default: true,
          description: 'Central entry point for all microservices'
        },
        {
          type: 'confirm',
          name: 'includeServiceDiscovery',
          message: 'Include Service Discovery?',
          default: true,
          description: 'Automatic service registration and discovery'
        }
      ]);
      
      answers.microservices = microservicesAnswers;
    }

    // Common features for both architectures
    const commonFeatures = await inquirer.prompt([
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
            checked: true,
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
          },
          { 
            name: '📊 Monitoring & Logging', 
            value: 'monitoring',
            checked: false,
            description: 'Winston logger & monitoring setup'
          }
        ]
      }
    ]);

    // Git initialization question (moved here to ensure projectName is available)
    const gitAnswer = await inquirer.prompt([
      {
        type: 'confirm',
        name: 'includeGit',
        message: 'Initialize Git repository?',
        default: true
      }
    ]);

    answers.features = commonFeatures.features;
    answers.includeGit = gitAnswer.includeGit;

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

    // Check if directory already exists (fixed path issue)
    const projectPath = path.join(process.cwd(), answers.projectName);
    if (await fileExists(projectPath)) {
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
    console.log(chalk.white(`Architecture: ${chalk.green(answers.architecture === 'monolithic' ? 'Monolithic' : 'Microservices')}`));
    console.log(chalk.white(`Project Name: ${chalk.green(answers.projectName)}`));
    console.log(chalk.white(`Module System: ${chalk.green(answers.moduleType.toUpperCase())}`));
    console.log(chalk.white(`Database: ${chalk.green(answers.database === 'none' ? 'None' : answers.database)}`));
    
    if (answers.architecture === 'microservices') {
      console.log(chalk.white(`Services: ${chalk.green(answers.microservices.services.join(', '))}`));
      console.log(chalk.white(`Message Queue: ${chalk.green(answers.microservices.messageQueue.join(', ') || 'None')}`));
      console.log(chalk.white(`API Gateway: ${chalk.green(answers.microservices.includeApiGateway ? 'Yes' : 'No')}`));
      console.log(chalk.white(`Service Discovery: ${chalk.green(answers.microservices.includeServiceDiscovery ? 'Yes' : 'No')}`));
    }
    
    console.log(chalk.white(`Features: ${chalk.green(answers.features.length > 0 ? answers.features.join(', ') : 'None')}`));
    console.log(chalk.white(`Git Init: ${chalk.green(answers.includeGit ? 'Yes' : 'No')}`));
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

    let generator;
    if (answers.architecture === 'monolithic') {
      generator = new MonolithicGenerator(answers);
    } else {
      generator = new MicroserviceGenerator(answers);
    }
    
    await generator.generate();
    
    console.log(chalk.green.bold('\n✅ Project generated successfully!'));
    
    // Enhanced next steps based on architecture
    console.log(chalk.blue('\n🎯 Next Steps:'));
    console.log(chalk.white(`1. cd ${answers.projectName}`));
    
    if (answers.architecture === 'monolithic') {
      console.log(chalk.white('2. npm install'));
      
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
    } else {
      // Microservices next steps
      console.log(chalk.white('2. Run: docker-compose up -d (to start all services)'));
      console.log(chalk.white('3. Check individual service README.md files for setup'));
      console.log(chalk.white('4. Access API Gateway at: http://localhost:3000'));
      
      if (answers.microservices.messageQueue.includes('bullmq')) {
        console.log(chalk.white('5. Redis dashboard available at: http://localhost:8081'));
      }
      
      if (answers.microservices.includeServiceDiscovery) {
        console.log(chalk.white('6. Service discovery available at: http://localhost:8500'));
      }
    }
    
    // Feature-specific tips
    if (answers.features.includes('docs')) {
      console.log(chalk.cyan('\n📚 API Documentation:'));
      if (answers.architecture === 'monolithic') {
        console.log(chalk.white('Visit http://localhost:3000/api-docs after starting the server'));
      } else {
        console.log(chalk.white('Visit http://localhost:3000/api-docs for API Gateway documentation'));
      }
    }
    
    if (answers.features.includes('auth')) {
      console.log(chalk.cyan('\n🔐 Authentication:'));
      if (answers.architecture === 'monolithic') {
        console.log(chalk.white('• Register: POST /api/auth/register'));
        console.log(chalk.white('• Login: POST /api/auth/login'));
        console.log(chalk.white('• Profile: GET /api/auth/profile (requires auth)'));
      } else {
        console.log(chalk.white('• Auth Service handles all authentication requests'));
        console.log(chalk.white('• JWT tokens are validated across all services'));
      }
    }
    
    if (answers.architecture === 'microservices') {
      console.log(chalk.cyan('\n🔗 Microservices Architecture:'));
      console.log(chalk.white('• Each service runs in its own container'));
      console.log(chalk.white('• Services communicate via HTTP/REST or message queues'));
      console.log(chalk.white('• API Gateway routes requests to appropriate services'));
      console.log(chalk.white('• Service discovery automatically manages service locations'));
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
      console.log(chalk.gray('• Error details:', error.stack));
    }
    process.exit(1);
  }
}