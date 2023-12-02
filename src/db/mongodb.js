import mongoose from 'mongoose';

export const URI = 'mongodb+srv://maximilianoariza01:ColXbla70bqiVlAm@cluster0.kjntekc.mongodb.net/ecommerce';

export const init = async () => {
  try {
    await mongoose.connect(URI);
    console.log('Conexion exitosa con la base de datos');
  } catch (error) {
    console.error('Error al conectar con la base de datos:', error.message);
  }
}
