import { OAuth2Client } from "google-auth-library";

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

const getGooglePayload = async (token: string) => {
    const ticket = await client.verifyIdToken({
        idToken: token,
        audience: process.env.GOOGLE_CLIENT_ID,
    });
    return ticket.getPayload();
};

const verifyGoogleToken = getGooglePayload;
const getGoogleUser = getGooglePayload;

export { verifyGoogleToken, getGoogleUser };
