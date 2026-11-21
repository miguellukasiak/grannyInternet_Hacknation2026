// jury.grannyinternet.me shows the jury page from the same deploy
export const onRequest = ({ request, next, env }) => {
  const url = new URL(request.url);
  if (url.hostname.startsWith("jury.") && url.pathname === "/") return env.ASSETS.fetch(new URL("/jury/", url));
  return next();
};
