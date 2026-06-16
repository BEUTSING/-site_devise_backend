<?php

namespace App\Controller;

use App\Entity\TauxChange;
use App\Service\TauxChangeService;
use OpenApi\Attributes as OA;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/api/v1/taux', name: 'app_taux_change_')]
#[OA\Tag(name: 'Taux de change')]
final class TauxChangeController extends AbstractController
{
    public function __construct(private TauxChangeService $tauxChangeService)
    {
    }

    #[Route('/list', name: 'list', methods: ['GET'])]
    #[IsGranted('ROLE_ADMIN')]
    #[OA\Get(
        path: "/api/v1/taux/list",
        summary: "List exchange rates",
        responses: [
            new OA\Response(
                response: 200,
                description: "List of exchange rates",
                content: new OA\JsonContent(
                    type: "array",
                    items: new OA\Items(
                        properties: [
                            new OA\Property(property: "id", type: "integer"),
                            new OA\Property(property: "monnaie", type: "string", example: "EUR"),
                            new OA\Property(property: "taux", type: "number", example: 650),
                            new OA\Property(property: "createdAt", type: "string", format: "date-time"),
                            new OA\Property(property: "updatedAt", type: "string", format: "date-time"),
                        ]
                    )
                )
            ),
        ]
    )]
    public function list(): JsonResponse
    {
        try {
            $data = array_map(fn (TauxChange $tauxChange) => $this->format($tauxChange), $this->tauxChangeService->getAll());

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

    #[Route('', name: 'create', methods: ['POST'])]
    #[IsGranted('ROLE_ADMIN')]
    #[OA\Post(
        path: "/api/v1/taux",
        summary: "Create an exchange rate",
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                properties: [
                    new OA\Property(property: "monnaie", type: "string", example: "EUR"),
                    new OA\Property(property: "taux", type: "number", example: 650),
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 201,
                description: "Exchange rate created successfully",
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: "id", type: "integer"),
                        new OA\Property(property: "monnaie", type: "string", example: "EUR"),
                        new OA\Property(property: "taux", type: "number", example: 650),
                        new OA\Property(property: "createdAt", type: "string", format: "date-time"),
                        new OA\Property(property: "updatedAt", type: "string", format: "date-time"),
                    ]
                )
            ),
        ]
    )]
    public function create(Request $request): JsonResponse
    {
        try {
            $tauxChange = $this->tauxChangeService->create($request);

            return $this->json([
                'status' => 'success',
                'data' => $this->format($tauxChange),
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
        path: "/api/v1/taux/{id}",
        summary: "Update an exchange rate",
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
                    new OA\Property(property: "monnaie", type: "string", example: "EUR"),
                    new OA\Property(property: "taux", type: "number", example: 650),
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 200,
                description: "Exchange rate updated successfully",
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: "id", type: "integer"),
                        new OA\Property(property: "monnaie", type: "string", example: "EUR"),
                        new OA\Property(property: "taux", type: "number", example: 650),
                        new OA\Property(property: "createdAt", type: "string", format: "date-time"),
                        new OA\Property(property: "updatedAt", type: "string", format: "date-time"),
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: "Exchange rate not found"
            )
        ]
    )]
    public function update(int $id, Request $request): JsonResponse
    {
        try {
            $tauxChange = $this->tauxChangeService->update($id, $request);

            return $this->json([
                'status' => 'success',
                'data' => $this->format($tauxChange),
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
        path: "/api/v1/taux/{id}",
        summary: "Delete an exchange rate",
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
                        new OA\Property(property: "message", type: "string", example: "Exchange rate deleted successfully")
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: "Exchange rate not found"
            )
        ]
    )]
    public function delete(int $id): JsonResponse
    {
        try {
            return $this->json([
                'status' => 'success',
                'message' => $this->tauxChangeService->delete($id),
            ], Response::HTTP_OK);
        } catch (\InvalidArgumentException $e) {
            return $this->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], Response::HTTP_NOT_FOUND);
        }
    }

    private function format(TauxChange $tauxChange): array
    {
        return [
            'id' => $tauxChange->getId(),
            'monnaie' => $tauxChange->getMonnaie(),
            'taux' => $tauxChange->getTaux(),
            'createdAt' => $tauxChange->getCreatedAt()?->format('Y-m-d H:i:s'),
            'updatedAt' => $tauxChange->getUpdatedAt()?->format('Y-m-d H:i:s'),
        ];
    }
}
