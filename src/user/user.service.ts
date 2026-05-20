import { Injectable } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { User, type UserDocument } from "./user.schema";
import type { Model } from "mongoose";
import type { CreateUserRequest } from "./dto/create-user-request.dto";
import { FileService } from "@/file/file.service";
import { UserStatus } from "./dto/user-status.enum";
import { Optional } from "@/common/class/optional";
import bcrypt from "bcrypt";

@Injectable()
export class UserService {
    constructor(
        @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
        private readonly fileService: FileService,
    ) { }

    private async hashPassword(password: string): Promise<string> {
        return await bcrypt.hash(password, 10);
    }

    public async list(page: number, limit: number): Promise<[Array<User>, number, number, number]> {
        const safePage = Number.isFinite(page) && page > 0 ? Math.floor(page) : 1;
        const safeLimit = Number.isFinite(limit) ? Math.floor(limit) : 10;
        const clampedLimit = Math.min(48, Math.max(1, safeLimit));
        const skip = (safePage - 1) * clampedLimit;

        const [result, total] = await Promise.all([
            this.userModel.find().skip(skip).limit(clampedLimit).exec(),
            this.userModel.countDocuments().exec(),
        ]);

        const users = await Promise.all(result.map(async u => {
            u.profilePictureUrl = await this.fileService.getSignedUrl(u.profilePictureUrl);
            return u;
        }));

        return [users, skip, clampedLimit, total];
    }

    public async get(id: string): Promise<Optional<User>> {
        return Optional.ofNullable(await this.userModel.findById(id).exec());
    }

    public async getByEmail(email: string): Promise<Optional<User>> {
        return Optional.ofNullable(await this.userModel.findOne({ email }).exec());
    }

    public async create(request: CreateUserRequest): Promise<string> {
        const user = await this.userModel.create({
            firstName: request.firstName,
            lastName: request.lastName,
            email: request.email,
            role: request.role,
            password: null,
            profilePictureUrl: this.fileService.placeholder,
            status: UserStatus.Unverified,
            permissions: request.permissions,
        });

        return user._id.toString();
    }

    public async activateAccount(uid: string, password: string): Promise<void> {
        const user = await this.userModel.findById(uid);
        if (!user) throw new Error(`User ${uid} not found`);

        user.password = await this.hashPassword(password);
        user.status = UserStatus.Active;
        await user.save();
    }

    public async updatePasswordById(id: string, password: string): Promise<void> {
        const user = await this.userModel.findById(id);
        if (!user) throw new Error(`User ${id} not found`);

        user.password = await this.hashPassword(password);
        await user.save();
    }

    public async setStatus(uid: string, status: UserStatus): Promise<void> {
        await this.userModel.updateOne({ _id: uid }, { status });
    }
}