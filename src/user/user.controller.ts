import { Body, Controller, Get, HttpException, InternalServerErrorException, NotFoundException, Param, Post } from "@nestjs/common";
import { UserService } from "./user.service";
import type { CreateUserRequest } from "./dto/create-user-request.dto";
import { Pag } from "@/common/decorator/pagination.decorator";
import { ListResponse } from "@/common/dto/list-response.dto";
import { ResponseMetadata } from "@/common/dto/response-metadata.dto";
import { ErrorResponse } from "@/common/dto/error-response.dto";
import { UserResponse } from "./dto/user-response.dto";
import { ItemResponse } from "@/common/dto/item-response.dto";

@Controller("users")
export class UserController {
    constructor(private readonly userService: UserService) { }

    @Post()
    public async createUser(@Body() data: CreateUserRequest) {
        try {
            const uid = await this.userService.create(data);
            const response = ItemResponse.Created();
            response.message = "User created.";
            response.data = uid;
            return response;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException(
                "An unexpected error occurred while creating the user.",
                { cause: error }
            );
        }
    }

    @Get(":id")
    public async getUser(@Param("id") id: string) {
        try {
            const user = (await this.userService.get(id))
                .orElseThrow(() => new NotFoundException("User not found."));

            const response = ItemResponse.OK();
            response.message = "User retrieved successfully.";
            response.data = UserResponse.fromUser(user);

            return response;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException(
                "An unexpected error occurred while retrieving the user.",
                { cause: error }
            );
        }
    }

    @Get()
    public async listUsers(@Pag("page") page: number, @Pag("limit") limit: number) {
        try {
            const [users, skip, lim, total] = await this.userService.list(page, limit);

            if (!users.length) {
                const error = new ErrorResponse();
                error.status = 404;
                error.message = "No users were found."
                error.error = "Not found";
                return error;
            }

            const response = new ListResponse();
            const metadata = new ResponseMetadata();

            metadata.limit = lim;
            metadata.offset = skip;
            metadata.total = total;

            response.data = users.map(UserResponse.fromUser);
            response.message = "User list retrieved successfully.";
            response.status = 200;
            response.meta = metadata;

            return response;
        } catch (error) {
            if (error instanceof HttpException) throw error;
            throw new InternalServerErrorException(
                "An unexpected error occurred while retrieving the user list.",
                { cause: error }
            );
        }
    }
}