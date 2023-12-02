import express from 'express';
import ProductManager from '../../dao/productManager.js';       //Product manager

const router = express.Router();

router.get('/products', async (req, res) => {                   //Ruta get para productos con paginación y filtrado
    try {
        const { page = 1, limit = 5, category, availability, sort, query } = req.query; //Parametros de consulta (pagina, limite, categoria, disponibilidad, orden)
        const criteria = {};

        if (query) {
            criteria.$text = { $search: query };
        } else {
            if (category) {
                criteria.category = category; //Filtro de categoria
            }
            if (availability !== undefined) {
                criteria.availability = availability; //Filtro de disponibilidad
            }
        }

        const options = { page, limit, sort: { price: sort === 'desc' ? -1 : 1 } };
        const result = await ProductManager.getProductsPaginated(criteria, options);

        const response = buildResponse(result, req);    //Objeto de la respuesta paginada
        console.log(response);
        //req.session.test = { response };
        //res.redirect('/products');
        
        res.render('products', { title: 'Productos', products: response, user: req.session.user });
    } catch (error) {
        console.error(error);
        res.status(500).json({ status: 'error', message: 'Error interno del servidor' });
    }
});

const buildResponse = (data, req) => {                       //Funcion para la respuesta paginada
    let { page = 1, limit = 5, category, availability, sort } = req.query;

    return {
        status: 'success',
        payload: data.docs.map(product => product.toJSON()), //Mapeo los productos a JSON
        totalPages: data.totalPages,
        prevPage: data.prevPage,
        nextPage: data.nextPage,
        page: data.page,
        hasPrevPage: data.hasPrevPage,
        hasNextPage: data.hasNextPage,
        prevLink: data.hasPrevPage
            ? `http://localhost:8080/api/products?limit=${limit}&page=${data.prevPage}${category ? `&category=${category}` : ''}${availability !== undefined ? `&availability=${availability}` : ''}${sort ? `&sort=${sort}` : ''}`
            : null,
        nextLink: data.hasNextPage
            ? `http://localhost:8080/api/products?limit=${limit}&page=${data.nextPage}${category ? `&category=${category}` : ''}${availability !== undefined ? `&availability=${availability}` : ''}${sort ? `&sort=${sort}` : ''}`
            : null,
    };
};

router.get('/products/:pid', async (req, res) => {          //Ruta para obtener un producto por su ID
    try {
        const { params: { pid } } = req;
        const product = await ProductManager.getProductByID(pid);
        res.status(200).json(product); 
    } catch (error) {
        console.error(error);
        res.status(error.statusCode || 500).json({ message: error.message });
    }
});

router.post('/products', async (req, res) => {              //Ruta para agregar un producto
    try {
        const { title, description, code, price, status, stock, category, thumbnail, availability } = req.body;

        if (!title || !description || !code || !price || !status || !stock || !category || !thumbnail || availability === undefined) { //Verificacion de campos obligatorios
            throw { statusCode: 400, message: 'Todos los campos son obligatorios' };
        }

        const product = req.body;
        const addedProduct = await ProductManager.addProduct(product); 
        res.status(201).json({ message: 'Producto agregado correctamente', product: addedProduct });
    } catch (error) {
        console.error(error);
        res.status(error.statusCode || 500).json({ message: error.message });
    }
});

router.put('/products/:pid', async (req, res) => {          //Ruta para actualizar un producto por su ID
    try {
        const { params: { pid }, body } = req; 
        await ProductManager.updateProduct(pid, body); 
        res.status(204).end(); 
    } catch (error) {
        console.error(error);
        res.status(error.statusCode || 500).json({ message: error.message });
    }
});

router.delete('/products/:pid', async (req, res) => {       //Ruta para eliminar un producto por su ID
    try {
        const { params: { pid } } = req;
        await ProductManager.deleteProduct(pid); 
        res.status(204).end();
    } catch (error) {
        console.error(error);
        res.status(error.statusCode || 500).json({ message: error.message });
    }
});


export default router;
