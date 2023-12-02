import { Router } from 'express';
import passport from 'passport';

const router = Router();

router.post('/sessions/register', passport.authenticate('register', { failureRedirect: '/register' }), (req, res) => {       //REGISTER
    res.redirect('/login');
})

router.post('/sessions/login', passport.authenticate('login', { failureRedirect: '/login' }), (req, res) => {               //LOGIN
    console.log('req.user', req.user);
    req.session.user = req.user;
    res.redirect('/api/products');
});

router.get('/sessions/github', passport.authenticate('github', { scope: ['user:email'] }), async (req,res)=>{});

router.get('/sessions/githubcallback', passport.authenticate('github', { failureRedirect: '/login' }), (req, res) => {
  req.session.user = req.user;
  res.redirect('/api/products');
})

router.get('/sessions/logout', (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            console.error(error);
            return res.status(500).send('Error interno del servidor');
        }
        res.redirect('/login');
    });
});

export default router;
