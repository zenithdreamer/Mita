import { Badge } from "../ui/badge";

export function StatusCard({ status }: { status: string }) {
    const getCustomClass = () => {
        if (status === "active") return "bg-green-500 border-green-500 text-white";
        if (status === "inactive") return "bg-red-500 border-red-500 text-white";
        return "bg-yellow-500 border-yellow-500 text-white";
    };

    return (
        <Badge variant={"outline"} className={getCustomClass()}>
            {status}
        </Badge>
    );
}