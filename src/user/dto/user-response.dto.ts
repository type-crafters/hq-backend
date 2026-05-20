import { UserStatus } from "./user-status.enum";
import { User } from "../user.schema";

interface UserResponseArgs {
	id: string;
	firstName: string;
	lastName: string;
	email: string;
	role: string;
	profilePictureUrl: string;
	status: UserStatus;
	createdAt: Date;
	updatedAt: Date;
}

export class UserResponse {
	public id!: string;
	public firstName!: string;
	public lastName!: string;
	public email!: string;
	public role!: string;
	public profilePictureUrl!: string;
	public status!: UserStatus;
	public createdAt!: Date;
	public updatedAt!: Date;

	private constructor({
		id,
		firstName,
		lastName,
		email,
		role,
		profilePictureUrl,
		status,
		createdAt,
		updatedAt,
	}: UserResponseArgs) {
		this.id = id;
		this.firstName = firstName;
		this.lastName = lastName;
		this.email = email;
		this.role = role;
		this.profilePictureUrl = profilePictureUrl;
		this.status = status;
		this.createdAt = createdAt;
		this.updatedAt = updatedAt;
	}

	public static fromUser(user: User): UserResponse {
		return new UserResponse({
			id: user._id.toString(),
			firstName: user.firstName,
			lastName: user.lastName,
			email: user.email,
			role: user.role,
			profilePictureUrl: user.profilePictureUrl,
			status: user.status,
			createdAt: user.createdAt,
			updatedAt: user.updatedAt
		});
	}
}

