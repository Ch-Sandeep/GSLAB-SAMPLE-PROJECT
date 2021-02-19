require('dotenv').config()
const express=require('express');

const fs=require('fs')

const app=express()

const jwt=require('jsonwebtoken');

app.use(express.json())


let refreshtokens=[]

app.get('/',(req,res)=>{
    res.send("Home page...").sendStatus(200)
})

app.get('/posts',authenticateToken,(req,res)=>{
    const users=JSON.parse(fs.readFileSync('users.json','utf-8'));
    res.json(users.filter(user=>user.name===req.user.name))
})

app.post('/token',(req,res)=>{
    const refreshtoken=req.body.token;
    if(refreshtoken==null)
    {
        return res.sendStatus(401);
    }
    if(!refreshtokens.includes(refreshtoken))
    {
        res.sendStatus(403)
    }
    jwt.verify(refreshtoken,process.env.REFRESH_TOKEN_SECRET,(err,user)=>{
        if(err)
        {
            res.sendStatus(403);
        }
        const accesstoken=generateaccesstoken({name:user.name})
        res.json({accesstoken:accesstoken})
    })
})

app.post('/login',(req,res)=>{
    const username=req.body.username

    const password=req.body.password
    const users=JSON.parse(fs.readFileSync('users.json','utf-8'));
    if(users.length==0)
    {
        res.end("user not found please signup")
    }
    for(var i=0;i<users.length;i++)
    {
        if(users[i].name===username)
        {
            if(users[i].password===password)
            {
                const user={name:username}
                const accesstoken=generateaccesstoken(user)
                const refreshtoken=jwt.sign(user,process.env.REFRESH_TOKEN_SECRET)
                refreshtokens.push(refreshtoken)
                return res.json({accesstoken:accesstoken,refreshtoken:refreshtoken});
            }
            else
            {
                res.end("Incorrect password...")
            }
        }
    }
    res.end("user not found please signup")
})

app.post('/signup',(req,res)=>{
    const username=req.body.username

    const password=req.body.password
    const users=JSON.parse(fs.readFileSync('users.json','utf-8'));
    var flag=false;
    for(var i=0;i<users.length;i++)
    {
        if(users[i].name===username)
        {
            flag=true;
            res.end("username exists please login...")
        }
    }
    if(flag==false)
    {
        const user={'name':username,'password':password}
        var userslist=JSON.parse(fs.readFileSync('users.json','utf-8'))
        userslist.push(user)
        try{
            fs.writeFileSync('users.json',JSON.stringify(userslist));
            res.end("new user added successfully...")
        }
        catch(err)
        {
            res.send("Error occurred...")
        }
    }
})

function authenticateToken(req,res,next)
{
    const authheader=req.headers['authorization']
    const token=authheader && authheader.split(' ')[1]
    if(token==null)
    {
        return res.sendStatus(401);
    }

    jwt.verify(token,process.env.ACCESS_TOKEN_SECRET,(err,user)=>{
        if(err)
        {
            console.log(err)
            return res.sendStatus(403)
        }
        req.user=user
        next()
    })
}

function generateaccesstoken(user)
{
    return jwt.sign(user,process.env.ACCESS_TOKEN_SECRET,{expiresIn:'5m'}) 
}
const port=process.env.PORT;

app.listen(port,function(){
    console.log("Server running on port " + port)
})