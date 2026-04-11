import { Injectable, InternalServerErrorException, NotFoundException } from "@nestjs/common";
import { InjectRepository } from "@nestjs/typeorm";
import { MongoRepository } from "typeorm";
import { User } from "./user.entity";
import { ObjectId } from "mongodb";
import { UserStatus } from "./dto/user-status.enum";

@Injectable()
export class UserService {
    constructor(@InjectRepository(User) private readonly userRepository: MongoRepository<User>) { }

    public async getById(id: string): Promise<User | null> {
        return await this.userRepository.findOneBy({ id: new ObjectId(id) });
    }

    public async existsByEmail(email: string): Promise<boolean> {
        return await this.userRepository.existsBy({ email });
    }

    public async getByEmail(email: string): Promise<User | null> {
        return await this.userRepository.findOneBy({ email });
    }

    public async update(id: string, user: Partial<User>): Promise<void> {
        const notFound = new NotFoundException("Project '" + id + "' not found.");
        if (!ObjectId.isValid(id)) throw notFound;

        const patch = Object.fromEntries(
            Object.entries(user).filter(([_, v]) => v != null)
        );

        if (Object.keys(patch).length === 0) return;

        try {
            const result = await this.userRepository.updateOne(
                { _id: new ObjectId(id) },
                { $set: patch }
            );

            if (result.matchedCount === 0) throw notFound;
        } catch {
            throw new InternalServerErrorException("Failed to update project.");
        }
    }

    public async updatePasswordById(id: string, passwordHash: string): Promise<void> {
        await this.update(id, { password: passwordHash });
    }

    public async activateById(id: string) {
        return this.update(id, { status: UserStatus.Active });
    }
}