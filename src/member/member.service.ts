import { Injectable, InternalServerErrorException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model, Types } from "mongoose";
import { Member, type MemberDocument } from "./member.schema";
import { CreateMemberRequest } from "./dto/create-member-request.dto";
import { UpdateMemberRequest } from "./dto/update-member-request.dto";
import { FileService } from "@/file/file.service";
import { Optional } from "@/common/class/optional";

@Injectable()
export class MemberService {
    constructor(
        @InjectModel(Member.name) private readonly memberModel: Model<MemberDocument>,
        private readonly fileService: FileService
    ) { }

    public async list(page: number, limit: number): Promise<MemberDocument[]> {
        const maxLimit = 24;

        const clamp = Math.min(limit, maxLimit);

        try {
            const members = await this.memberModel
                .find()
                .sort({ createdAt: -1 })
                .skip(clamp * (page - 1))
                .limit(clamp)
                .exec();

            return await Promise.all(
                members.map(async (member) => {
                    member.profilePictureUrl =
                        await this.fileService.getSignedUrl(
                            member.profilePictureUrl
                        );

                    return member;
                })
            );
        } catch {
            throw new InternalServerErrorException(
                "Failed to fetch member list."
            );
        }
    }

    public async get(id: string): Promise<Optional<MemberDocument>> {
        if (!Types.ObjectId.isValid(id)) {
            return Optional.empty();
        }

        const member = await this.memberModel
            .findById(id)
            .exec();

        if (!member) {
            return Optional.empty();
        }

        member.profilePictureUrl =
            await this.fileService.getSignedUrl(
                member.profilePictureUrl
            );

        return Optional.of(member);
    }

    public async create(request: CreateMemberRequest): Promise<MemberDocument> {
        return await this.memberModel.create({
            ...request,
            bio: request.bio ?? "",
            profilePictureUrl:  request.profilePictureUrl ?? this.fileService.placeholder
        });
    }

    public async update(id: string, request: UpdateMemberRequest): Promise<Optional<MemberDocument>> {
        if (!Types.ObjectId.isValid(id)) {
            return Optional.empty();
        }

        const patch = Object.fromEntries(
            Object.entries(request).filter(
                ([_, value]) => value != null
            )
        );

        if (Object.keys(patch).length === 0) {
            return this.get(id);
        }

        try {
            const member = await this.memberModel.findById(id);

            if (!member) {
                return Optional.empty();
            }

            Object.assign(member, patch);

            const saved = await member.save();

            return Optional.of(saved);
        } catch {
            throw new InternalServerErrorException("Failed to update member.");
        }
    }

    public async delete(id: string): Promise<Optional<MemberDocument>> {
        if (!Types.ObjectId.isValid(id)) {
            return Optional.empty();
        }

        try {
            const member = await this.memberModel.findByIdAndDelete(id).exec();

            if (!member) {
                return Optional.empty();
            }

            return Optional.of(member);
        } catch {
            throw new InternalServerErrorException(
                "Failed to delete member."
            );
        }
    }
}
