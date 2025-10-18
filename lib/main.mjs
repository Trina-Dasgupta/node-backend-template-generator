import inquirer from 'inquirer';
import chalk from 'chalk';
import { MonolithicGenerator } from './generators/monolithicGenerator.mjs';
import { fileExists } from './utils/fileUtils.mjs';

export async function main() {
  console.log(chalk.blue.bold('\n🚀 Node.js Backend Generator'));
  console.log(chalk.gray('Creating a professional Node.js backend template...\n'));

  try {
    const answers = await inquirer.prompt([
      {
        type: 'input',
        name: 'projectName',
        message: 'Enter your project name:',
        default: 'my-backend',
        validate: (input) => {
          if (!input.trim()) {
            return 'Project name cannot be empty!';
          }
          if (input.includes(' ')) {
            return 'Project name cannot contain spaces!';
          }
          return true;
        }
      },
      {
        type: 'list',
        name: 'moduleType',
        message: 'Choose module system:',
        choices: [
          { name: 'ES Modules (MJS)', value: 'mjs' },
          { name: 'CommonJS (CJS)', value: 'cjs' }
        ]
      },
      {
        type: 'list',
        name: 'database',
        message: 'Choose database ORM:',
        choices: [
          { name: 'Mongoose (MongoDB)', value: 'mongoose' },
          { name: 'Sequelize (SQL)', value: 'sequelize' },
          { name: 'Prisma', value: 'prisma' },
          { name: 'None', value: 'none' }
        ]
      },
      {
        type: 'checkbox',
        name: 'features',
        message: 'Select additional features:',
        choices: [
          { name: 'Authentication (JWT)', value: 'auth' },
          { name: 'File Upload', value: 'fileUpload' },
          { name: 'Email Service', value: 'email' },
          { name: 'API Documentation', value: 'docs' },
          { name: 'Docker Support', value: 'docker' }
        ]
      }
    ]);

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

    const generator = new MonolithicGenerator(answers);
    await generator.generate();
    
    console.log(chalk.green.bold('\n✅ Project generated successfully!'));
    console.log(chalk.blue('\nNext steps:'));
    console.log(chalk.white(`cd ${answers.projectName}`));
    console.log(chalk.white('npm install'));
    
    if (answers.database !== 'none') {
      console.log(chalk.white('Setup your database configuration in .env'));
    }
    
    console.log(chalk.white('npm start'));
    console.log(chalk.gray('\nHappy coding! 🎉'));

  } catch (error) {
    console.error(chalk.red('Error generating project:'), error);
    process.exit(1);
  }
}