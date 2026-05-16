import { Body, Controller, Delete, Get, Param, Patch, Post, Query } from "@nestjs/common";
import { MemberService } from "./member.service";
import { CreateMemberRequest } from "./dto/create-member-request.dto";
import { UpdateMemberRequest } from "./dto/update-member-request.dto";
import { RequiresPermission } from "@/common/decorator/requires-permission.decorator";
import type { PaginationParams } from "@/common/dto/pagination-params.dto";

@Controller("members")
export class MemberController {
    constructor(private readonly memberService: MemberService) { }

    @Get()
    public async listMembers(@Query() params: PaginationParams) {
        return await this.memberService.list(params.page, params.limit);
    }

    @Get(":id")
    public async getMember(@Param("id") id: string) {
        return await this.memberService.get(id);
    }

    @Post()
    @RequiresPermission("create:member")
    public async createMember(@Body() request: CreateMemberRequest) {
        return await this.memberService.create(request);
    }

    @Patch(":id")
    @RequiresPermission("update:member")
    public async updateMember(@Param("id") id: string, @Body() request: UpdateMemberRequest) {
        await this.memberService.update(id, request);
    }

    @Delete(":id")
    @RequiresPermission("delete:member")
    public async deleteMember(@Param("id") id: string) {
        await this.memberService.delete(id);
    }
}