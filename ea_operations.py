import random
from config import CHARSET, POPULATION_SIZE, PASSWORD_LENGTH, GENERATIONS, MUTATION_RATE, ELITE_SIZE
from fitness import fitness
from handshake_parser import parse_handshake

def mutate(individual, charset, mutation_rate=0.1):
    chars = list(individual)
    for i in range(len(chars)):
        if random.random() < mutation_rate:
            chars[i] = random.choice(charset)
    return ''.join(chars)


def tournament_selection(population, fitnesses, num_parents, tournament_size=3):
    selected_parents = []
    pop_size = len(population)

    for _ in range(num_parents):
        # Pick tournament candidates randomly
        competitors = random.sample(range(pop_size), tournament_size)
        # Find the best fitness among competitors (assuming higher fitness is better)
        best = max(competitors, key=lambda idx: fitnesses[idx])
        selected_parents.append(population[best])

    return selected_parents


def initialize_population(pop_size, length, charset):
    
    population = []
    for _ in range(pop_size):
        individual = ''.join(random.choice(charset) for _ in range(length))
        population.append(individual)
    return population

def crossover(parent1, parent2):
    if len(parent1) != len(parent2):
        raise ValueError("Parents must be the same length")

    length = len(parent1)
    # Choose two crossover points
    pt1 = random.randint(1, length - 2)
    pt2 = random.randint(pt1 + 1, length - 1)

    offspring1 = parent1[:pt1] + parent2[pt1:pt2] + parent1[pt2:]
    offspring2 = parent2[:pt1] + parent1[pt1:pt2] + parent2[pt2:]

    return offspring1, offspring2

def elitism(population, fitnesses, offspring, elite_size):
    # Pair population and fitness, sort by fitness descending
    sorted_pop = [x for _, x in sorted(zip(fitnesses, population), key=lambda pair: pair[0], reverse=True)]

    # Keep elites
    new_population = sorted_pop[:elite_size]

    # Fill the rest with offspring (assumes offspring is big enough)
    remaining_spots = len(population) - elite_size
    new_population += offspring[:remaining_spots]

    return new_population

def evolutionary_algorithm(charset, pop_size, pw_length, generations, mutation_rate, elite_size):
    # 1. Initialize population
    population = initialize_population(pop_size, pw_length, charset)

    for gen in range(generations):
        # 2. Evaluate fitness of all individuals
        fitnesses = [fitness(ind, parse_handshake("/mnt/c/Users/yavuz/internship/wifi_crack/wpa.full.cap")) for ind in population]

        # 3. Log best individual
        best_fitness = max(fitnesses)
        best_individual = population[fitnesses.index(best_fitness)]
        print(f"Gen {gen}: Best fitness = {best_fitness}, Best password = {best_individual}")

        # 4. Selection
        parents = tournament_selection(population, fitnesses, pop_size - elite_size)

        # 5. Crossover
        offspring = []
        for i in range(0, len(parents), 2):
            if i+1 < len(parents):
                child1, child2 = crossover(parents[i], parents[i+1])
                offspring.extend([child1, child2])
            else:
                offspring.append(parents[i])

        # 6. Mutation
        offspring = [mutate(child, charset, mutation_rate) for child in offspring]

        # 7. Elitism: preserve top elites from current population
        population = elitism(population, fitnesses, offspring, elite_size)

        # 8. Stop condition (optional): perfect fitness
        if best_fitness == 0:  # Assuming fitness=0 means perfect MIC match
            print("Password found!")
            break

    return best_individual

def main():
    best_password = evolutionary_algorithm(
        charset=CHARSET,
        pop_size=POPULATION_SIZE,
        pw_length=PASSWORD_LENGTH,
        generations=GENERATIONS,
        mutation_rate=MUTATION_RATE,
        elite_size=ELITE_SIZE
    )
    print(f"Best password found: {best_password}")

if __name__ == "__main__":
    main()

