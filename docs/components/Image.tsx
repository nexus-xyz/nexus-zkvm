import Image from "next/image";

export function NexusImage({ src, alt, width, height }) {
  return (
    <Image
      src={src}
      alt={alt}
      width={width}
      height={height}
      style={{ borderRadius: 5 }}
    />
  );
}
