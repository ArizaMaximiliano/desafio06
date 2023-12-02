import mongoose from 'mongoose';

//Esquema del carrito
const CartSchema = new mongoose.Schema({
  products: [{
    product: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Product',
      required: true
    },
    quantity: {
      type: Number,
      default: 1
    }
  }]
});

const Cart = mongoose.model('Cart', CartSchema);

export default Cart;
