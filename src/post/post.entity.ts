import type { ObjectId } from "mongodb";
import { Entity, ObjectIdColumn } from "typeorm";

@Entity("posts")
export class Post {
    @ObjectIdColumn()
    public id!: ObjectId;
}