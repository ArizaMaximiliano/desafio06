import path from 'path';
import { fileURLToPath } from 'url';

import bcrypt from 'bcrypt';


//Obtener el directorio actual
const __filename = fileURLToPath(import.meta.url);

export const __dirname = path.dirname(__filename);

//Clase manejo de excepciones
export class Exception extends Error {
  constructor(message, status) {
    super(message);
    this.statusCode = status;
  }
};

//hash y validacion
export const createHash = (password) => bcrypt.hashSync(password, bcrypt.genSaltSync(10));

export const isValidPassword = (password, user) => bcrypt.compareSync(password, user.password);