import Cart from '../models/cartModel.js';    //Modelo del carrito
import { Exception } from '../utils.js';      //Clase de excepciones

export default class CartManager {
  
  static async createCart() {                 //Metodo para crear un nuevo carrito
    const newCart = await Cart.create({});
    console.log('Carrito creado correctamente.');
    return newCart;
  }
 
  static async getCart(cartId) {              //Metodo para obtener un carrito por su ID
    const cart = await Cart.findById(cartId).populate('products.product').lean(); 
    if (!cart) {
      throw new Exception('Carrito no encontrado', 404);
    }
    return cart;
  }

  static async addProductToCart(cartId, productId, quantity) {      //Metodo para agregar un producto a un carrito
    const cart = await Cart.findById(cartId);
    if (!cart) {
      throw new Exception('Carrito no encontrado', 404);
    }

    const existingProduct = cart.products.find((product) => product.product._id.equals(productId)); 

    if (existingProduct) {                                          //Actualizacion de la cantidad si el producto ya existe en el carrito
      if (typeof existingProduct.quantity === 'number' && typeof quantity === 'number') {
        existingProduct.quantity += quantity;
      } else {
        throw new Error('La cantidad no es un número válido');
      }
    } else {
      cart.products.push({ product: productId, quantity });
    }

    await cart.save();
    console.log('Producto agregado al carrito correctamente.');
    return cart;
  }
 
  static async updateCart(cartId, updatedCart) {                  //Metodo para actualizar un carrito por su ID
    const cart = await Cart.findByIdAndUpdate(cartId, updatedCart, { new: true }); 
    if (!cart) {
      throw new Exception('Carrito no encontrado', 404); 
    }
    console.log('Carrito actualizado correctamente.');
    return cart;
  }
  
  static async updateProductInCart(cartId, productId, updatedQuantity) {    //Metodo para actualizar la cantidad de un producto en el carrito por su ID (carrito y producto)
    const cart = await Cart.findById(cartId); 
    if (!cart) {
      throw new Exception('Carrito no encontrado', 404); 
    }

    const existingProduct = cart.products.find((product) => product.product._id.equals(productId)); 

    if (existingProduct) {
      existingProduct.quantity = updatedQuantity; 
    } else {
      throw new Exception('Producto no encontrado en el carrito', 404); 
    }

    await cart.save(); 
    console.log('Cantidad del producto en el carrito actualizada correctamente.');
    return cart; 
  }
  
  static async deleteProductFromCart(cartId, productId) {         //Metodo para eliminar un producto del carrito por ID (carrito y producto)
    const cart = await Cart.findById(cartId); 
    if (!cart) {
      throw new Exception('Carrito no encontrado', 404); 
    }

    cart.products = cart.products.filter((product) => !product.product._id.equals(productId));

    await cart.save(); 
    console.log('Producto eliminado del carrito correctamente.');
    return cart;
  }

  static async deleteCart(cartId) {                               //Metodo para eliminar carrito por su ID
    const cart = await Cart.findByIdAndRemove(cartId); 
    if (!cart) {
      throw new Exception('Carrito no encontrado', 404); 
    }
    console.log('Carrito eliminado correctamente.');
    return cart;
  }
}