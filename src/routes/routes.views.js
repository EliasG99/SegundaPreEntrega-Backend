// Imports

import { Router } from 'express';
import __dirname from '../utils.js'; //Importamos utils para poder trabvajar con rutas absolutas
import ProductManagerMongo from '../dao/ProductManagerMongo.js';
import CartManagerMongo from '../dao/CartManagerMongo.js';
import { productsModel } from '../dao/models/products.model.js';

// Definitions

export const router = Router();
const productManager = new ProductManagerMongo();
const cartManager = new CartManagerMongo();

// Middlewares

function auth (req, res, next) { // Middleware to check if a user is authenticated
  if (!req.session.user){
    return res.redirect('/login')
    
  }
  next();
}

// Methods

router.get('/', auth, async (req,res) => { // Homepage View

  try {
    res.setHeader('Content-Type','text/html');
    res.status(200).render('home')

  } catch (error) {
        res.setHeader('Content-Type','application/json');
        console.log(error.message)
        return res.status(400).json({error:`error`});
  }
})

router.get('/products', auth, async (req,res) => { // Products View

  try {
    res.setHeader('Content-Type','text/html');
    let {limit=10, page=1, category, sort={}} = req.query
    let sortOption = {}; // Set the sorting, it can be ascending or descending
    let query = {};
    let {name, email, role} = req.session.user // Getting the session user data to display welcome message
    if(category) {
      query.description = { $regex: category, $options: 'i' }; // Regular expression so that it can accept upper and lowecase text
    }
    if (sort === 'asc') {
      sortOption = {price: 1};
    } else if (sort === 'desc') {
      sortOption = {price: -1};
    } else {
      console.log('The sort option can be asc or desc');
    }
    limit = parseInt(limit); // Get the limit query for products
    page = parseInt(page)
    console.log(`Queries received in view router LIMIT: ${limit}, PAGE: ${page}, QUERY: ${query}, SORT: ${sort}`);
    let products = await productManager.getProducts(limit, page, query, sortOption); // Fetches the paginate data of all products
    let {totalPages, hasNextPage, hasPrevPage, prevPage, nextPage} = products
    //console.log('Pagination values from DB: ', totalPages, hasNextPage, hasPrevPage, prevPage, nextPage); 
    res.status(200).render('products' , {
      data: products.docs,
      totalPages, hasNextPage, hasPrevPage, prevPage, nextPage, limit, page, sort, query,
      name, email, role
    })

  } catch (error) {
        res.setHeader('Content-Type','application/json');
        console.log(error.message)
        return res.status(400).json({error:`error`});
  }
})

router.get('/realtimeproducts', auth, async (req,res) => { // Realtime products View

  try {  
    res.setHeader('Content-Type','text/html');
    let data = await productManager.getProducts(); // Retrieves the products from the DB
    res.status(200).render('realTimeProducts' , {data: data.docs})

  } catch (error) {
        res.setHeader('Content-Type','application/json');
        return res.status(400).json({error:`error`});
  }
})

router.get('/chatapp', auth, async (req,res) => {

  try {  
    res.setHeader('Content-Type','text/html');
    res.status(200).render('chat') // Chat app view

  } catch (error) {
        res.setHeader('Content-Type','application/json');
        return res.status(400).json({error:`error`});
  }
})

router.get('/carts/:cid', auth, async (req,res) => { // Cart view
  let cartId = req.params.cid;
  try {
    res.setHeader('Content-Type','text/html');
    let data = await cartManager.getCartById(cartId);
    if (!data) {
      return res.status(404).render('error', { message: 'Cart not found' });
    }
    data.products.forEach(product => {
      console.log(product.productId);
    });

    //console.log(data)
    res.status(200).render('carts', {
      products: data.products,
      cartId: cartId
    }) // Renders the carts view

  } catch (error) {
        res.setHeader('Content-Type','application/json');
        return res.status(400).json({error:`error`});
  }
})

//  Reports (Aggregation) Views

router.get('/reports', auth, async (req,res) => { // Aggregation view

  try {  
    let data = await productsModel.aggregate(
      [
        { // Stage 1 (Project)
          $match: {description: 'laptop'}
        },
        { // Stage 2 (Sort by price before they are grouped)
          $sort: {price: -1}
        },
        { //stage 3 (Group)
          $group: {
            _id: '$description',
            products: {$push: '$$ROOT'}
          }
        },
      ]
      
      )
    if (!data) {
      res.status(400).json({error: 'The report could not be created'});
    } else {
      res.status(200).json(data);
    }

  } catch (error) {
        res.setHeader('Content-Type','application/json');
        return res.status(400).json({error:`error`});
  }
})

// Sessions Views

router.get('/signup', async (req,res) => {

  try {
    let {error} = req.query;
    res.setHeader('Content-Type','text/html');
    res.status(200).render('signup', {error}) // Sign Up View

  } catch (error) {
        res.setHeader('Content-Type','application/json');
        return res.status(400).json({error:`error`});
  }
})

router.get('/login', async (req,res) => {

  try {  
    let {error, message} = req.query
    res.setHeader('Content-Type','text/html');
    res.status(200).render('login', {error, message}) // Login View 
  } catch (error) {
        res.setHeader('Content-Type','application/json');
        return res.status(400).json({error:`error`});
  }
})

router.get('/profile', auth, async (req,res) => {

  try {  
    let user = req.session.user;
    res.setHeader('Content-Type','text/html');
    res.status(200).render('profile', {user}) // Profile View
  } catch (error) {
        res.setHeader('Content-Type','application/json');
        res.status(400).json({error:`error`});
  }
})