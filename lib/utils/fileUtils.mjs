import fs from 'fs-extra';

export async function fileExists(path) {
  try {
    await fs.access(path);
    return true;
  } catch {
    return false;
  }
}

export async function copyDirectory(src, dest) {
  await fs.copy(src, dest);
}

export async function createFile(path, content) {
  await fs.ensureFile(path);
  await fs.writeFile(path, content);
}