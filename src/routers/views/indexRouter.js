import { Router } from 'express';

const router = Router();

//Render products-cart
router.get('/products', (req, res) => {
  //res.render('products', { title: 'Productos', products: req.session.test.response, user: req.session.user });
});

router.get('/cart', (req, res) => {
  //res.render('cart', { title: 'Carrito' });
});

//Render login-register
router.get('/login', (req, res) => {
  res.render('login', { title: 'Login' });
});

router.get('/register', (req, res) => {
  res.render('register', { title: 'Register' });
});

export default router;
