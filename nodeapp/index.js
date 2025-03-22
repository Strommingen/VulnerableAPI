const express = require('express');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser')
const db = require('./db');
const app = express();
const path = require('path');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
dotenv.config();
app.use(express.json());
app.use(express.urlencoded({extended: true}));

const port = 3000;
const jwtKey = process.env.JWT_KEY;

// Error handling using middleware 
app.use((err, req, res, next) =>{
    const status = err.status || 500; // errors in other CRUD operations will use this function and will default to 500 if nothing else is stated by the server.

    res.status(status).json({
        error: {
            code: status,
            message: err.message || "Something went wrong", // again will default to the left value
        },
    });
});

// limiter preventing DOS attacks
const limiter = rateLimit({
    windowMS: 1*60*1000, // 1 min
    max: 5,
    message: {error: "Too many requests at once, wait for a while and come back later"}
});
app.use('/api/', limiter);


async function verifyUser(taskId, userId) { // verify that the task is assigned to the requested user and that the task exists
    const [taskCheck] = await db.execute(`SELECT user_id FROM Tasks WHERE task_id=?`, [taskId]);
    console.log(taskCheck)
    if (taskCheck.length===0){
        const error = new Error(`Task with id ${taskId} not found`);
        error.status=404;
        throw error;
    }
    if (taskCheck[0].user_id !== userId) {
        const error = new Error(`Unauthorized to modify this task`);
        error.status = 403;
        throw error;
    }
}

app.use(cookieParser());
// token verfification
const verifyToken = (req,res,next) =>{
    try{
        const token = req.cookies.jwt;
        // const token = req.headers['authorization'];

        if(!token){
            const error = new Error('Access Denied');
            error.status=403;
            throw error;
        }
        const verified = jwt.decode(token, jwtKey);
        req.user = verified;
        
        next();
    } catch(err){
        if (err.name === 'TokenExpiredError') { // expired token changed to 401
            const error = new Error('Token expired');
            error.status = 401;
            next(error);
        }else if (err.name === 'JsonWebTokenError') {// invalid token changed to 401
            const error = new Error('Invalid Token');
            error.status = 401;
            next(error);
        }   else {
            next(err);
        }
    }
}

// endpoints
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});


// login with JWT
app.post('/login', async(req,res,next) =>{
    try{
        const {username, password} = req.body;
        
        if (!username || !password){
            const error = new Error('Invalid or missing credentials');
            error.status=400;
            throw error;
        }
        
        const [rows] = await db.execute(`SELECT user_id, username, password FROM Users WHERE username = ?`, [username]);
        if (rows.length===0){ // no result means no user found 
            const error = new Error(`User not found`);
            error.status=404;
            throw error;
        }

        const user = rows[0];

        if (bcrypt.compareSync(password,user.password)){
            const token = jwt.sign({userName: username, userId: rows[0].user_id}, jwtKey, {expiresIn:'1h'});
            res.cookie('jwt', token, {
                httpOnly:true,
                sameSite:'strict',
                maxAge:3600000 // 1h
            });
            return res.status(200).json({message: "Login successfull"});
            //return res.json({token});
        } else{
            const error = new Error('Unauthorized');
            error.status=401;
            throw error;
        }
    } catch(err){
        next(err);
    }
});

//all tasks
app.get('/tasks', verifyToken, async (req,res,next) =>{
    try{
        //userId = await getUserId(req.user);
        const {userId} = req.user; 
        const [rows] = await db.execute(`SELECT 
            t.task_id, 
            t.task_name, 
            t.description, 
            t.status, 
            u.user_id
            FROM Tasks t 
            LEFT JOIN Users u ON t.user_id = u.user_id
            WHERE u.user_id = ?`, [userId]); // can only see tasks of person logged in
        if(rows.length === 0) {
            const error = new Error('No tasks found');
            error.status = 404;
            throw error; // triggers the catch statement with the error
        }
        res.json(rows);
    } catch(err){
        next(err); // passes the error to the error handler
    }
});
// specific task
app.get('/tasks/:id', verifyToken, async (req,res,next) =>{
    try{
        const {userId} = req.user; 
        const taskId=parseInt(req.params.id, 10);
        if(!taskId || isNaN(taskId)){
            const error = new Error('Invalid or missing id parameter');
            error.status = 400;
            throw error;
        }

        await verifyUser(taskId, userId);

        const [rows] = await db.execute(`SELECT 
            t.task_id, 
            t.task_name, 
            t.description, 
            t.status,
            u.user_id
            FROM Tasks t 
            LEFT JOIN Users u ON t.user_id = u.user_id 
            WHERE t.task_id= ? AND t.user_id =?`, [taskId,userId]); // can only see task of person logged in

        res.json(rows);
    } catch(err){
        next(err);
    }
});

app.post('/tasks', verifyToken, async (req, res, next) =>{
    try{
        const {taskName, description, status} = req.body;
        const {userId} = req.user;

        const [result] = await db.execute(`INSERT INTO Tasks
            (task_name, 
            description,
            status,
            user_id)
            VALUES
            (?,?,?,?)`,
            [taskName, description, status, userId]
        );
        if (result.affectedRows===0){
            const error = new Error(`Task not created`);
            error.status=404;
            throw error;
        }

        const [task] = await db.execute(
            `SELECT * FROM Tasks WHERE task_id = ?`,
            [result.insertId] 
        );
        res.status(201).json(task);
    } catch(err){
        next(err);
    }
});

app.put('/tasks/:id', verifyToken, async (req,res, next) =>{
    try{
        const {userId} = req.user;
        const taskId=parseInt(req.params.id, 10);
        if(!taskId || isNaN(taskId)){
            const error = new Error('Invalid or missing id parameter');
            error.status = 400;
            throw error;
        }
        const {taskName, description, status} = req.body;

        await verifyUser(taskId, userId);

        const [result] = await db.execute(`UPDATE Tasks
            SET task_name = ?, 
            description =?, 
            status =? 
            WHERE task_id =?`,
            [taskName,description,status,taskId] // can only update task of person logged in
        );
        if (result.affectedRows===0){
            const error = new Error(`Task not created`);
            error.status=404;
            throw error;
        }
        const [task] = await db.execute(
            `SELECT * FROM Tasks WHERE task_id = ?`,
            [taskId] 
        );
        res.status(200).json(task);
    } catch(err){
        next(err);
    }
});

app.delete('/tasks/:id', verifyToken, async (req, res, next) =>{
    const {userId} = req.user;
    const taskId=parseInt(req.params.id, 10);
    try{
        if(!taskId || isNaN(taskId)){
            const error = new Error('Invalid or missing id parameter');
            error.status = 400;
            throw error;
        }
        
        await verifyUser(taskId, userId);

        const [result] = await db.execute(`DELETE FROM Tasks WHERE task_id = ?`, [taskId]); // can only delete task of person logged in
        if (result.affectedRows===0){
            const error = new Error(`Task with id ${taskId} not found`);
            error.status=404;
            throw error;
        }
        res.status(200).json({message: 'Task deleted successfully'})
    } catch(err){
        next(err);
    }
});

app.listen(port, (err) => {
    if (err) {
        console.error("Server failed to start: ", err);
    } else {
        console.log(`Server running on port http://localhost:${port}`);
    }
});