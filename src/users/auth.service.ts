import { BadRequestException, Injectable } from "@nestjs/common";
import { UsersService } from "./users.service";
import { scrypt as _scrypt, randomBytes } from "crypto";
import { promisify } from "util";

const scrypt = promisify(_scrypt)

@Injectable()
export class AuthService {
    constructor(private userService: UsersService) { }

    async signup(email: string, password: string) {
        // See if email is in use
        const users = await this.userService.find(email)
        if (users.length) {
            throw new BadRequestException('Email in use!')
        }

        // Hash the users password
        // Generate a salt
        const salt = randomBytes(8).toString('hex')

        // Hash the salt and the password together
        const hash = (await scrypt(password, salt, 32)) as Buffer

        // Join the hashed result and the salt together
        const result = `${salt}.${hash.toString('hex')}`


        // Create a new user and save it
        const user = this.userService.create(email, result)

        // return the user
        return user
    }
}