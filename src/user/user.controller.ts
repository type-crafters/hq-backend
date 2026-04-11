import  { Body, Controller, Get, Param, ParseIntPipe, Post, Query } from "@nestjs/common";
import  { UserService } from "./user.service";
import { User } from "@/common/decorator/user.decorator";


@Controller("users")
export class UserController {
    constructor(private readonly userService: UserService) { }

    @Get()
    public listUsers(@Query("page", ParseIntPipe) page: number, @Query("limit", ParseIntPipe) limit: number) {
        
    }

    @Get(":id")
    public getUser(@Param("id") id: string) {
        
    }

    @Post("invite")
    public inviteUser(@Body() body: string,  @User("id") id: string, @User("permissions") permissions: string) {
        
    }
}