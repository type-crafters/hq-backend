import { Transform } from "class-transformer";

export const DefaultInt = (defaultValue: number) =>
  Transform(({ value }) => {
    if (value === undefined || value === null || value === "") {
      return defaultValue;
    }

    if (typeof value === "string") {
      const parsed = parseInt(value, 10);
      return isNaN(parsed) ? defaultValue : parsed;
    }

    return value;
});