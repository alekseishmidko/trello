import { Priority } from '@prisma/client';
import { Transform } from 'class-transformer';
import { IsEnum, IsOptional, IsString } from 'class-validator';

export class TaskDto {
  @IsString()
  name: string;

  @IsOptional()
  @IsOptional()
  isCompleted?: boolean;

  @IsString()
  @IsOptional()
  createdAt?: string;

  @IsEnum(Priority)
  @IsOptional()
  @Transform(({ value }) => ('' + value).toLowerCase())
  priority?: Priority;
}
