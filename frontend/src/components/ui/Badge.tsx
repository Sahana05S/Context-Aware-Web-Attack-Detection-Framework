import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "../../utils/cn"

const badgeVariants = cva(
    "inline-flex items-center rounded px-2 py-0.5 text-[10px] font-semibold tracking-wider transition-colors",
    {
        variants: {
            variant: {
                default:
                    "border border-transparent bg-primary/15 text-primary",
                secondary:
                    "border border-transparent bg-secondary text-secondary-foreground",
                destructive:
                    "bg-[#e13d3d]/15 text-[#e13d3d] border border-[#e13d3d]/30",
                outline:
                    "border border-border text-muted-foreground",
                success:
                    "bg-[#73bf69]/15 text-[#73bf69] border border-[#73bf69]/30",
                warning:
                    "bg-[#f2c14a]/15 text-[#f2c14a] border border-[#f2c14a]/30",
                danger:
                    "bg-[#e13d3d]/15 text-[#e13d3d] border border-[#e13d3d]/30",
                info:
                    "bg-[#5794f2]/15 text-[#5794f2] border border-[#5794f2]/30",
            },
        },
        defaultVariants: {
            variant: "default",
        },
    }
)

export interface BadgeProps
    extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> { }

function Badge({ className, variant, ...props }: BadgeProps) {
    return (
        <div className={cn(badgeVariants({ variant }), className)} {...props} />
    )
}

export { Badge, badgeVariants }
