#1. Any authenticate user can updated any task

#code block:
export async function PATCH(req: NextRequest, { params }: Params) {
  const user = await getCurrentUser(req);
  if (!user) return unauthorized();

  const { id } = await params;

  const body = await req.json().catch(() => null);
  const parsed = updateTaskSchema.safeParse(body);
  if (!parsed.success) return badRequest("invalid input", parsed.error.flatten());

  const existing = await prisma.task.findUnique({ where: { id } });
  if (!existing) return notFound("task not found");

  const task = await prisma.task.update({
    where: { id },
    data: parsed.data,
    include: {
      assignee: { select: { id: true, name: true, email: true } },
    },
  });

  return NextResponse.json({ task });
}

#category : Security Bug
#Severity : Critical
#Description:The Patch task endpoint authenticates the user but does not verify the user belongs to the task's project before updating it, This allowed any logged in-user to modify title , status , assigneed or any other detail related to task.
#Proposed Fix:
Load the task , getProjectMembership(user.id, existing.projectId);


#2.Task Search uses unsafe raw SQL .
export async function GET(req: NextRequest, { params }: Params) {
  const user = await getCurrentUser(req);
  if (!user) return unauthorized();

  const { id: projectId } = await params;
  const membership = await getProjectMembership(user.id, projectId);
  if (!membership) return forbidden("you are not a member of this project");

  const q = req.nextUrl.searchParams.get("q");

  if (q) {
    // search across title and description
    const sql = `
      SELECT id, project_id, title, description, status, assignee_id, created_by_id, position, created_at, updated_at
      FROM tasks
      WHERE project_id = '${projectId}'
        AND (title ILIKE '%${q}%' OR description ILIKE '%${q}%')
      ORDER BY position ASC
    `;
    const tasks = await prisma.$queryRawUnsafe(sql);
    return NextResponse.json({ tasks });
  }

  const tasks = await prisma.task.findMany({
    where: { projectId },
    include: {
      assignee: { select: { id: true, name: true, email: true } },
    },
    orderBy: [{ status: "asc" }, { position: "asc" }],
  });

  return NextResponse.json({ tasks });
}


#Categorty : Security 
#Severity : Critical 
$Description : The task GET method for searching purpose uses unsafe raw SQL, this endpoint maximize the risk of SQL injection by using raw SQL query here, the 'q' paramter directly used in raw SQL query string and executes it with '@queryRawUnsafe',A crafted query can alter SQL logic, expose more rows or possibly break the endpoint.
#Recommended fix: Rplaced RAW SQL query with Prisma, like :
from RAW query :
(
  title ILIKE '%q%'
  OR
  description ILIKE '%q%'
)

To Prisma:OR: [
  {
    title: {
      contains: q,
      mode: "insensitive",
    },
  },
  {
    description: {
      contains: q,
      mode: "insensitive",
    },
  },
]


RAW Query:
WHERE project_id = ?
AND (
  title ILIKE ?
  OR description ILIKE ?
)

To Prisma:
where: {
  projectId,

  OR: [
    { title: { contains: q, mode: "insensitive" } },
    { description: { contains: q, mode: "insensitive" } },
  ],
}






