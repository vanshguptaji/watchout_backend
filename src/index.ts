import dotenv from 'dotenv';
import { httpServer } from './app';
import connectDB from './db/index';

dotenv.config({
    path: './.env',
});

const port: number = parseInt(process.env.PORT || '8080');

connectDB()
    .then(() => {
        httpServer.listen(port, () => {
            console.log('------------------------------------------------');
            console.log(`🚀 Server started successfully on port: ${port}`);
            console.log(`🔗 URL: http://localhost:${port}`);
            console.log(`✅ Database connected successfully`);
            console.log(`🔌 WebSocket server running`);
            console.log('⌛ Server is waiting for requests...');
            console.log('------------------------------------------------');
        });
    })
    .catch((err: unknown) => {
        console.error('❌ MONGO DB connection failed!!!', err);
        process.exit(1);
    });