'use server'

import {prisma} from '@/db/prisma'
import bcrypt from 'bcryptjs'
import {logEvent} from "@/utils/sentry";
import {removeAuthCookie, setAuthCookie, signAuthToken} from "@/lib/auth";

type ResponseResult = {
    success: boolean,
    message: string
}

// Register new user
export async function registerUser(prevState: ResponseResult, fromData: FormData): Promise<ResponseResult> {
    try {
        const name = fromData.get('name') as string;
        const email = fromData.get('email') as string;
        const password = fromData.get('password') as string;

        if (!name || !email || !password) {
            logEvent('Validation Error: Missing register fields', 'auth', {name, email}, 'warning')

            return {success: false, message: 'All fields are required'}
        }


        // Check if user exists
        const existingUser = await prisma.user.findUnique({
            where: {email}
        })

        if (existingUser) {
            logEvent(`Registration is failed: User already exists - ${email}`, 'auth', {email}, 'warning')

            return {success: false, message: 'User already exists'}
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10)

        // Create user
        const user = await prisma.user.create({
            data: {
                name,
                email,
                password: hashedPassword,
            }
        })

        // Sign and set auth token
        const token = await signAuthToken({userId: user.id})
        await setAuthCookie(token)

        logEvent(`User registered successfully: ${email}`, 'auth', {userId: user.id, email}, 'info')

        return {success: true, message: 'Registration successful'}

    } catch (err) {
        logEvent(
            'Unexpected error during registration',
            'auth',
            {},
            'error',
            err
        )
        return {success: false, message: 'Something went wrong, please try again'}
    }
}

// Log user out and remove auth cookie
export async function logoutUser(): Promise<{ success: boolean, message: string }> {
    try {
        await removeAuthCookie()

        logEvent(`User logged out successfully`, 'auth', {}, 'info')

        return {success: true, message: 'Logged out successful'}
    } catch (err) {
        logEvent('Unexpected error during logout', 'auth', {}, 'error', err)

        return {success: false, message: 'Something went wrong, please try again'}
    }
}

// Log user in
export async function loginUser(prevState: ResponseResult, formData: FormData): Promise<ResponseResult> {
    try {
        const email = formData.get('email') as string
        const password = formData.get('password') as string

        if (!email || !password) {
            logEvent('Validation error: Missing login fields', 'auth', {email}, 'warning')
            return {success: false, message: 'Email and password are required'}
        }

        const user = await prisma.user.findUnique({
            where: {email}
        })

        if (!user || !user.password) {
            logEvent(`Login failed: User not found - ${email}`, 'auth', {email}, 'warning')

            return {success: false, message: 'Invalid email or password'}
        }

        const isMatch = await bcrypt.compare(password, user.password)

        if (!isMatch) {
            logEvent(`Login failed: Incorrect password`, 'auth', {email}, 'warning')

            return {success: false, message: 'Invalid email or password'}
        }

        const token = await signAuthToken({userId: user.id})
        await setAuthCookie(token)

        return {success: true, message: 'Login successful'}
    } catch (err) {
        logEvent('Unexpected error during login', 'auth', {}, 'error', err)

        return {success: false, message: 'Something went wrong, please try again'}
    }
}