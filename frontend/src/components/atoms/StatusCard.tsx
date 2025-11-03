export function StatusCard({ status }: { status: string }) {
    const bgClass =
        status === "active" ? "bg-green-500" : status === "inactive" ? "bg-red-500" : "bg-yellow-500";

    return (
        <div className={`items-center inline-flex ${bgClass} px-2 rounded-md`}>
            <p className="font-bold text-white">{status}</p>
        </div>
    );
}