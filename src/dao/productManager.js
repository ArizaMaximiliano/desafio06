import Product from '../models/productModel.js';    //Modelo de Producto
import { Exception } from '../utils.js';            //Clase de excepciones

export default class ProductManager {
                                                    
  static async addProduct(product) {                //Metodo para agregar un producto a la base de datos
    try {
      const newProduct = await Product.create(product); 
      console.warn('Producto agregado correctamente.');
      return newProduct;
    } catch (error) {
      throw new Exception('Error al agregar el producto', 500);
    }
  }
  
  static async getProducts(query) {                 //Metodo para obtener productos
    try {
      const products = await Product.find(query); 
      return products;
    } catch (error) {
      throw new Exception('Error al obtener los productos', 500); 
    }
  }
 
  static async getProductByID(id) {                 //Metodo para obtener un producto por su ID
    try {
      const product = await Product.findById(id); 
      if (product) {
        console.warn(`Producto con el ID (${id}) encontrado:`);
        return product;
      } else {
        throw new Exception(`Error: ID (${id}) no existente.`, 404); 
      }
    } catch (error) {
      throw new Exception(`Error al obtener el producto - ${error.message}`, 500);
    }
  }

  static async updateProduct(id, updatedProduct) {  //Metodo para actualizar un producto por su ID
    try {
      const product = await Product.findByIdAndUpdate(id, updatedProduct, { new: true }); 
      if (product) {
        console.warn(`Producto con ID (${id}) actualizado correctamente.`, product);
        return product;
      } else {
        throw new Exception(`Error: ID (${id}) no existente.`, 404);
      }
    } catch (error) {
      throw new Exception(`Error al actualizar el producto - ${error.message}`, 500); 
    }
  }

  static async deleteProduct(id) {                 //Metodo para eliminar un producto por su ID
    try {
      const product = await Product.findByIdAndRemove(id); 
      if (product) {
        console.warn(`Producto con ID (${id}) eliminado correctamente.`, product);
        return product;
      } else {
        throw new Exception(`Error: ID (${id}) no existente.`, 404);
      }
    } catch (error) {
      throw new Exception(`Error al eliminar el producto - ${error.message}`, 500);
    }
  }

 
  static async getProductsPaginated(criteria, options) {  //Metodo para obtener productos paginados
    try {
      const result = await Product.paginate(criteria, options);

      return result;
    } catch (error) {
      throw new Exception(`Error al obtener productos paginados - ${error.message}`, 500);
    }
  }
}
