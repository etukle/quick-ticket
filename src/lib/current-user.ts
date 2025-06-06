import {getAuthCookie, verifyAuthToken} from "./auth";
import {prisma} from "@/db/prisma";

type AuthPayload = {
    userId: string;
}

export async function getCurrentUser() {
    try {
        const token = await getAuthCookie();
        if (!token) return null

        const payload = (await verifyAuthToken(token)) as AuthPayload;

        if (!payload?.userId) return null;

        const user = await prisma.user.findUnique({
            where: {id: payload.userId},
            select: {
                id: true,
                email: true,
                name: true
            }
        })

        return user
    } catch (err) {
        console.log('Error getting the current user', err);
        return null;
    }
}