import dotenv from 'dotenv';
import connectDB from './db/index';
import { app } from './app';

dotenv.config({
    path: './.env',
});

const port: number = parseInt(process.env.PORT || '8080');

connectDB()
    .then(() => {
        app.listen(port, () => {
            console.log('------------------------------------------------');
            console.log(`🚀 Server started successfully on port: ${port}`);
            console.log(`🔗 URL: http://localhost:${port}`);
            console.log(`✅ Database connected successfully`);
            // console.log('------------------------------------------------');
            // console.log('📝 API Documentation available at /api/docs');
            console.log('⌛ Server is waiting for requests...');
            console.log('------------------------------------------------');
        });
    })
    .catch((err: unknown) => {
        console.error('❌ MONGO DB connection failed!!!', err);
        process.exit(1);
    });