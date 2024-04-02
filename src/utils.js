import {fileURLToPath} from 'url';
import { dirname } from 'path';
import bcrypt from 'bcrypt';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const saltRounds = 10; 

export default __dirname;

export async function createHash(password){ // A function that hashes a password using Bcrypt

  return bcrypt.hash(password, saltRounds)

}

export async function validatePassword(user, password) {

  return bcrypt.compare(password, user.password)

}