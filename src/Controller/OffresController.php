<?php

namespace App\Controller;

use App\Entity\Offres;
use App\Service\OffresService;
use OpenApi\Attributes as OA;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/api/v1/offres', name: 'app_offres_')]
#[OA\Tag(name: 'Offres')]
final class OffresController extends AbstractController
{
    public function __construct(private OffresService $offresService)
    {
    }

    #[Route('/list', name: 'list', methods: ['GET'])]
    #[OA\Get(
        path: "/api/v1/offres/list",
        summary: "List offres",
        parameters: [
            new OA\Parameter(
                name: "deviseSource",
                in: "query",
                required: false,
                schema: new OA\Schema(type: "string"),
                description: "Devise source (ex: XAF)"
            ),
            new OA\Parameter(
                name: "deviseCible",
                in: "query",
                required: false,
                schema: new OA\Schema(type: "string"),
                description: "Devise cible (ex: EUR)"
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: "List of offres",
                content: new OA\JsonContent(
                    type: "array",
                    items: new OA\Items(
                        properties: [
                            new OA\Property(property: "id", type: "integer"),
                            new OA\Property(property: "montant", type: "number", example: 1000),
                            new OA\Property(property: "statut", type: "string", example: "active"),
                            new OA\Property(property: "image", type: "string", nullable: true),
                            new OA\Property(
                                property: "deviseSource",
                                type: "object",
                                nullable: true,
                                properties: [
                                    new OA\Property(property: "id", type: "integer"),
                                    new OA\Property(property: "monnaie", type: "string", example: "EUR"),
                                    new OA\Property(property: "taux", type: "number", example: 650),
                                ]
                            ),
                            new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                            new OA\Property(
                                property: "user",
                                type: "object",
                                nullable: true,
                                properties: [
                                    new OA\Property(property: "name", type: "string", example: "Jean Dupont"),
                                    new OA\Property(property: "phone", type: "string", example: "699000000"),
                                ]
                            ),
                            new OA\Property(property: "createdAt", type: "string", format: "date-time"),
                        ]
                    )
                )
            ),
        ]
    )]
    public function list(Request $request): JsonResponse
    {
        try {
            $deviseSource = $request->query->get('deviseSource');
            $deviseCible = $request->query->get('deviseCible');

            if ($deviseSource !== null && $deviseCible !== null) {
                $data = $this->offresService->getByBoth($deviseSource, $deviseCible);
            } elseif ($deviseSource !== null) {
                $data = $this->offresService->getByDeviseSource($deviseSource);
            } elseif ($deviseCible !== null) {
                $data = $this->offresService->getByDeviseCible($deviseCible);
            } else {
                $data = $this->offresService->getAll();
            }

            $data = array_map(fn(Offres $offre) => $this->format($offre), $data);

            return $this->json([
                'status' => 'success',
                'data' => $data,
            ], Response::HTTP_OK);
        } catch (\RuntimeException $e) {
            return $this->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], Response::HTTP_NOT_FOUND);
        }
    }

    #[Route('/{id}', name: 'show', methods: ['GET'])]
    #[OA\Get(
        path: "/api/v1/offres/{id}",
        summary: "Show an offre",
        parameters: [
            new OA\Parameter(
                name: "id",
                in: "path",
                required: true,
                schema: new OA\Schema(type: "integer")
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: "Offre details",
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: "id", type: "integer"),
                        new OA\Property(property: "montant", type: "number", example: 1000),
                        new OA\Property(property: "statut", type: "string", example: "active"),
                        new OA\Property(property: "image", type: "string", nullable: true),
                        new OA\Property(
                            property: "deviseSource",
                            type: "object",
                            nullable: true,
                            properties: [
                                new OA\Property(property: "id", type: "integer"),
                                new OA\Property(property: "monnaie", type: "string", example: "EUR"),
                                new OA\Property(property: "taux", type: "number", example: 650),
                            ]
                        ),
                        new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                        new OA\Property(
                            property: "user",
                            type: "object",
                            nullable: true,
                            properties: [
                                new OA\Property(property: "name", type: "string", example: "Jean Dupont"),
                                new OA\Property(property: "phone", type: "string", example: "699000000"),
                            ]
                        ),
                        new OA\Property(property: "createdAt", type: "string", format: "date-time"),
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: "Offre not found"
            )
        ]
    )]
    public function show(int $id): JsonResponse
    {
        try {
            $offre = $this->offresService->getOne($id);

            return $this->json([
                'status' => 'success',
                'data' => $this->format($offre),
            ], Response::HTTP_OK);
        } catch (\InvalidArgumentException $e) {
            return $this->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], Response::HTTP_NOT_FOUND);
        }
    }

    #[Route('', name: 'create', methods: ['POST'])]
    #[IsGranted('ROLE_ADMIN')]
    #[OA\Post(
        path: "/api/v1/offres",
        summary: "Create an offre",
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                required: ["montant", "deviseSource", "deviseCible", "statut", "tauxChangeId"],
                properties: [
                    new OA\Property(property: "montant", type: "number", example: 1000),
                    new OA\Property(property: "deviseSource", type: "string", example: "XAF"),
                    new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                    new OA\Property(property: "statut", type: "string", example: "active"),
                    new OA\Property(property: "image", type: "string", nullable: true),
                    new OA\Property(property: "tauxChangeId", type: "integer", example: 1),
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 201,
                description: "Offre created successfully",
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: "id", type: "integer"),
                        new OA\Property(property: "montant", type: "number", example: 1000),
                        new OA\Property(property: "statut", type: "string", example: "active"),
                        new OA\Property(property: "image", type: "string", nullable: true),
                        new OA\Property(
                            property: "deviseSource",
                            type: "object",
                            nullable: true,
                            properties: [
                                new OA\Property(property: "id", type: "integer"),
                                new OA\Property(property: "monnaie", type: "string", example: "EUR"),
                                new OA\Property(property: "taux", type: "number", example: 650),
                            ]
                        ),
                        new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                        new OA\Property(
                            property: "user",
                            type: "object",
                            nullable: true,
                            properties: [
                                new OA\Property(property: "name", type: "string", example: "Jean Dupont"),
                                new OA\Property(property: "phone", type: "string", example: "699000000"),
                            ]
                        ),
                        new OA\Property(property: "createdAt", type: "string", format: "date-time"),
                    ]
                )
            ),
        ]
    )]
    public function create(Request $request): JsonResponse
    {
        try {
            $offre = $this->offresService->create($request);

            return $this->json([
                'status' => 'success',
                'data' => $this->format($offre),
            ], Response::HTTP_CREATED);
        } catch (\InvalidArgumentException $e) {
            return $this->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], Response::HTTP_BAD_REQUEST);
        } catch (\RuntimeException $e) {
            return $this->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], Response::HTTP_CONFLICT);
        }
    }

    #[Route('/{id}', name: 'update', methods: ['PUT'])]
    #[IsGranted('ROLE_ADMIN')]
    #[OA\Put(
        path: "/api/v1/offres/{id}",
        summary: "Update an offre",
        parameters: [
            new OA\Parameter(
                name: "id",
                in: "path",
                required: true,
                schema: new OA\Schema(type: "integer")
            )
        ],
        requestBody: new OA\RequestBody(
            content: new OA\JsonContent(
                properties: [
                    new OA\Property(property: "montant", type: "number", example: 1000),
                    new OA\Property(property: "deviseSource", type: "string", example: "XAF"),
                    new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                    new OA\Property(property: "statut", type: "string", example: "active"),
                    new OA\Property(property: "image", type: "string", nullable: true),
                    new OA\Property(property: "tauxChangeId", type: "integer", example: 1),
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 200,
                description: "Offre updated successfully",
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: "id", type: "integer"),
                        new OA\Property(property: "montant", type: "number", example: 1000),
                        new OA\Property(property: "statut", type: "string", example: "active"),
                        new OA\Property(property: "image", type: "string", nullable: true),
                        new OA\Property(
                            property: "deviseSource",
                            type: "object",
                            nullable: true,
                            properties: [
                                new OA\Property(property: "id", type: "integer"),
                                new OA\Property(property: "monnaie", type: "string", example: "EUR"),
                                new OA\Property(property: "taux", type: "number", example: 650),
                            ]
                        ),
                        new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                        new OA\Property(
                            property: "user",
                            type: "object",
                            nullable: true,
                            properties: [
                                new OA\Property(property: "name", type: "string", example: "Jean Dupont"),
                                new OA\Property(property: "phone", type: "string", example: "699000000"),
                            ]
                        ),
                        new OA\Property(property: "createdAt", type: "string", format: "date-time"),
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: "Offre not found"
            )
        ]
    )]
    public function update(int $id, Request $request): JsonResponse
    {
        try {
            $offre = $this->offresService->update($id, $request);

            return $this->json([
                'status' => 'success',
                'data' => $this->format($offre),
            ], Response::HTTP_OK);
        } catch (\InvalidArgumentException $e) {
            return $this->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], Response::HTTP_NOT_FOUND);
        } catch (\RuntimeException $e) {
            return $this->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], Response::HTTP_CONFLICT);
        }
    }

    #[Route('/{id}', name: 'delete', methods: ['DELETE'])]
    #[IsGranted('ROLE_ADMIN')]
    #[OA\Delete(
        path: "/api/v1/offres/{id}",
        summary: "Delete an offre",
        parameters: [
            new OA\Parameter(
                name: "id",
                in: "path",
                required: true,
                schema: new OA\Schema(type: "integer")
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: "Deleted",
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: "message", type: "string", example: "Offre deleted successfully")
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: "Offre not found"
            )
        ]
    )]
    public function delete(int $id): JsonResponse
    {
        try {
            $message = $this->offresService->delete($id);

            return $this->json([
                'status' => 'success',
                'message' => $message['message'],
            ], Response::HTTP_OK);
        } catch (\InvalidArgumentException $e) {
            return $this->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], Response::HTTP_NOT_FOUND);
        }
    }

    private function format(Offres $offre): array
    {
        $user = $offre->getUser();
        $tauxChange = $offre->getTauxChange();

        return [
            'id' => $offre->getId(),
            'montant' => $offre->getMontant(),
            'statut' => $offre->getStatut(),
            'image' => $offre->getImage(),
            'deviseSource' => $tauxChange ? [
                'id' => $tauxChange->getId(),
                'monnaie' => $tauxChange->getMonnaie(),
                'taux' => $tauxChange->getTaux(),
            ] : null,
            'deviseCible' => $offre->getDeviseCible(),
            'user' => $user ? [
                'name' => $user->getName(),
                'phone' => $user->getPhone(),
            ] : null,
            'createdAt' => $offre->getCreatedAt()?->format('Y-m-d H:i:s'),
        ];
    }
}
