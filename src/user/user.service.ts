import { BadRequestException, Injectable, InternalServerErrorException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Types, type Model } from "mongoose";
import { User, type UserDocument } from "./user.schema";
import { UserStatus } from "./dto/user-status.enum";
import type { UpdateUserRequest } from "./dto/update-user-request.dto";
import { FileService } from "@/file/file.service";
import { MailService } from "@/mail/mail.service";
import { ConfigService } from "@nestjs/config";
import { Optional } from "@/common/class/optional";

@Injectable()
export class UserService {
    constructor(
        @InjectModel(User.name) private readonly userModel: Model<UserDocument>,
        private readonly fileService: FileService,
        private readonly mailService: MailService,
        private readonly config: ConfigService
    ) { }

    public async list(page: number, limit: number): Promise<UserDocument[]> {
        const maxLimit = 24;
        const clamp = Math.min(limit, maxLimit);

        try {
            const users = await this.userModel
                .find()
                .sort({ createdAt: -1 })
                .skip(clamp * (page - 1))
                .limit(clamp)
                .exec();

            return await Promise.all(
                users.map(async (user) => {
                    user.profilePictureUrl =
                        await this.fileService.getSignedUrl(
                            user.profilePictureUrl
                        );

                    return user;
                })
            );
        } catch {
            throw new InternalServerErrorException("Failed to fetch user list.");
        }
    }

    public async existsByEmail(email: string): Promise<boolean> {
        const user = await this.userModel
            .findOne({ email })
            .select("_id")
            .exec();

        return user != null;
    }

    public async create(
        firstName: string,
        lastName: string,
        email: string,
        permissions: string[]
    ): Promise<UserDocument> {
        if (await this.existsByEmail(email)) {
            throw new BadRequestException(
                "User with this email already exists."
            );
        }

        const user = await this.userModel.create({
            firstName,
            lastName,
            email,
            password: "",
            profilePictureUrl: this.fileService.placeholder,
            status: UserStatus.Unverified,
            permissions: [...new Set(permissions)]
        });

        const url = new URL(
            "/email/verify",
            this.config.getOrThrow("PAGE_URL")
        );

        url.searchParams.set(
            "sub",
            user.id.toString()
        );

        await this.mailService.renderAndSend(
            email,
            "Confirm your email address",
            "verify-email.ejs",
            {
                firstName: user.firstName,
                url: url.toString()
            }
        );

        return user;
    }

    public async getById(id: string): Promise<Optional<UserDocument>> {
        if (!this.isValidObjectId(id)) {
            return Optional.empty();
        }

        const user = await this.userModel
            .findById(id)
            .exec();

        if (!user) {
            return Optional.empty();
        }

        user.profilePictureUrl =
            await this.fileService.getSignedUrl(
                user.profilePictureUrl
            );

        return Optional.of(user);
    }

    public async getByEmail(email: string): Promise<Optional<UserDocument>> {
        const user = await this.userModel
            .findOne({ email })
            .exec();

        if (!user) {
            return Optional.empty();
        }

        user.profilePictureUrl =
            await this.fileService.getSignedUrl(
                user.profilePictureUrl
            );

        return Optional.of(user);
    }

    public async update(id: string, patch: UpdateUserRequest): Promise<Optional<UserDocument>> {
        if (!this.isValidObjectId(id)) {
            return Optional.empty();
        }

        const sanitized = Object.fromEntries(
            Object.entries(patch).filter(
                ([_, value]) => value != null
            )
        );

        if (Object.keys(sanitized).length === 0) {
            return this.getById(id);
        }

        try {
            const user =
                await this.userModel.findById(id);

            if (!user) {
                return Optional.empty();
            }

            Object.assign(user, sanitized);

            const saved = await user.save();

            return Optional.of(saved);
        } catch {
            throw new InternalServerErrorException(
                "Failed to update user."
            );
        }
    }

    public async updatePasswordById(id: string, passwordHash: string): Promise<Optional<UserDocument>> {
        return await this.update(id, {
            password: passwordHash
        });
    }

    public async activateById(id: string): Promise<Optional<UserDocument>> {
        return await this.update(id, {
            status: UserStatus.Active
        });
    }

    private isValidObjectId(id: string): boolean {
        return Types.ObjectId.isValid(id);
    }
}
