// Ejecuta el kernel add_arrays traducido por metal2vulkan y comprueba que c[i] == a[i] + b[i].
//
//   clang -O1 -o run_add_arrays run_add_arrays.c -lvulkan
//   ./run_add_arrays add_arrays.vulkan1.2.spv
//
// Interfaz del SPIR-V (set 0): binding 0 = a, 1 = b, 2 = c (buffers de almacenamiento) y 48 bytes de
// push constants (la región de dispatch de metal2vulkan; todo a cero = origen 0). 64 hilos por grupo.
#include <vulkan/vulkan.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define N 64
#define CHECK(call)                                                              \
	do {                                                                         \
		VkResult r_ = (call);                                                    \
		if (r_ != VK_SUCCESS) {                                                  \
			fprintf(stderr, "FALLO %s:%d  %s = %d\n", __FILE__, __LINE__, #call, r_); \
			return 1;                                                            \
		}                                                                        \
	} while (0)

static uint32_t find_memory(VkPhysicalDevice pd, uint32_t bits, VkMemoryPropertyFlags want) {
	VkPhysicalDeviceMemoryProperties mp;
	vkGetPhysicalDeviceMemoryProperties(pd, &mp);
	for (uint32_t i = 0; i < mp.memoryTypeCount; ++i)
		if ((bits & (1u << i)) && (mp.memoryTypes[i].propertyFlags & want) == want)
			return i;
	return UINT32_MAX;
}

int main(int argc, char** argv) {
	if (argc != 2) {
		fprintf(stderr, "uso: %s shader.spv\n", argv[0]);
		return 2;
	}

	FILE* f = fopen(argv[1], "rb");
	if (!f) {
		perror("abrir SPIR-V");
		return 2;
	}
	fseek(f, 0, SEEK_END);
	long spv_size = ftell(f);
	fseek(f, 0, SEEK_SET);
	uint32_t* spv = malloc(spv_size);
	if (fread(spv, 1, spv_size, f) != (size_t)spv_size) return 2;
	fclose(f);

	VkApplicationInfo app = { .sType = VK_STRUCTURE_TYPE_APPLICATION_INFO, .apiVersion = VK_API_VERSION_1_2 };
	VkInstanceCreateInfo ici = { .sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, .pApplicationInfo = &app };
	VkInstance inst;
	CHECK(vkCreateInstance(&ici, NULL, &inst));

	uint32_t n = 1;
	VkPhysicalDevice pd;
	VkResult er = vkEnumeratePhysicalDevices(inst, &n, &pd);
	if ((er != VK_SUCCESS && er != VK_INCOMPLETE) || n == 0) {
		fprintf(stderr, "sin dispositivos Vulkan\n");
		return 1;
	}
	VkPhysicalDeviceProperties props;
	vkGetPhysicalDeviceProperties(pd, &props);
	VkPhysicalDeviceFeatures feats;
	vkGetPhysicalDeviceFeatures(pd, &feats);
	printf("GPU: %s (Vulkan %u.%u)  shaderInt64=%u\n", props.deviceName, VK_VERSION_MAJOR(props.apiVersion),
		VK_VERSION_MINOR(props.apiVersion), feats.shaderInt64);

	uint32_t qn = 0;
	vkGetPhysicalDeviceQueueFamilyProperties(pd, &qn, NULL);
	VkQueueFamilyProperties* qf = malloc(qn * sizeof *qf);
	vkGetPhysicalDeviceQueueFamilyProperties(pd, &qn, qf);
	uint32_t family = UINT32_MAX;
	for (uint32_t i = 0; i < qn; ++i)
		if (qf[i].queueFlags & VK_QUEUE_COMPUTE_BIT) { family = i; break; }
	if (family == UINT32_MAX) return 1;

	float prio = 1.0f;
	VkDeviceQueueCreateInfo qci = { .sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO, .queueFamilyIndex = family,
		.queueCount = 1, .pQueuePriorities = &prio };
	// no se activa ninguna feature: el shader debe funcionar con las de serie
	VkDeviceCreateInfo dci = { .sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO, .queueCreateInfoCount = 1, .pQueueCreateInfos = &qci };
	VkDevice dev;
	CHECK(vkCreateDevice(pd, &dci, NULL, &dev));
	VkQueue queue;
	vkGetDeviceQueue(dev, family, 0, &queue);

	VkBuffer buf[3];
	VkDeviceMemory mem[3];
	float* map[3];
	for (int i = 0; i < 3; ++i) {
		VkBufferCreateInfo bci = { .sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO, .size = N * sizeof(float),
			.usage = VK_BUFFER_USAGE_STORAGE_BUFFER_BIT, .sharingMode = VK_SHARING_MODE_EXCLUSIVE };
		CHECK(vkCreateBuffer(dev, &bci, NULL, &buf[i]));
		VkMemoryRequirements mr;
		vkGetBufferMemoryRequirements(dev, buf[i], &mr);
		uint32_t mt = find_memory(pd, mr.memoryTypeBits, VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT);
		if (mt == UINT32_MAX) return 1;
		VkMemoryAllocateInfo mai = { .sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, .allocationSize = mr.size, .memoryTypeIndex = mt };
		CHECK(vkAllocateMemory(dev, &mai, NULL, &mem[i]));
		CHECK(vkBindBufferMemory(dev, buf[i], mem[i], 0));
		CHECK(vkMapMemory(dev, mem[i], 0, VK_WHOLE_SIZE, 0, (void**)&map[i]));
	}
	for (int i = 0; i < N; ++i) {
		map[0][i] = (float)i;
		map[1][i] = 1000.0f + 2.0f * i;
		map[2][i] = -1.0f;
	}

	VkDescriptorSetLayoutBinding binds[3];
	for (int i = 0; i < 3; ++i)
		binds[i] = (VkDescriptorSetLayoutBinding){ .binding = i, .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
			.descriptorCount = 1, .stageFlags = VK_SHADER_STAGE_COMPUTE_BIT };
	VkDescriptorSetLayoutCreateInfo dslci = { .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO, .bindingCount = 3, .pBindings = binds };
	VkDescriptorSetLayout dsl;
	CHECK(vkCreateDescriptorSetLayout(dev, &dslci, NULL, &dsl));

	VkPushConstantRange pcr = { .stageFlags = VK_SHADER_STAGE_COMPUTE_BIT, .offset = 0, .size = 48 };
	VkPipelineLayoutCreateInfo plci = { .sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO, .setLayoutCount = 1,
		.pSetLayouts = &dsl, .pushConstantRangeCount = 1, .pPushConstantRanges = &pcr };
	VkPipelineLayout pl;
	CHECK(vkCreatePipelineLayout(dev, &plci, NULL, &pl));

	VkShaderModuleCreateInfo smci = { .sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO, .codeSize = spv_size, .pCode = spv };
	VkShaderModule sm;
	CHECK(vkCreateShaderModule(dev, &smci, NULL, &sm));

	VkComputePipelineCreateInfo cpci = { .sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO, .layout = pl,
		.stage = { .sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO, .stage = VK_SHADER_STAGE_COMPUTE_BIT, .module = sm, .pName = "main" } };
	VkPipeline pipe;
	CHECK(vkCreateComputePipelines(dev, VK_NULL_HANDLE, 1, &cpci, NULL, &pipe));
	printf("pipeline de cómputo creado\n");

	VkDescriptorPoolSize ps = { .type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, .descriptorCount = 3 };
	VkDescriptorPoolCreateInfo dpci = { .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO, .maxSets = 1, .poolSizeCount = 1, .pPoolSizes = &ps };
	VkDescriptorPool dp;
	CHECK(vkCreateDescriptorPool(dev, &dpci, NULL, &dp));
	VkDescriptorSetAllocateInfo dsai = { .sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO, .descriptorPool = dp, .descriptorSetCount = 1, .pSetLayouts = &dsl };
	VkDescriptorSet ds;
	CHECK(vkAllocateDescriptorSets(dev, &dsai, &ds));
	VkDescriptorBufferInfo dbi[3];
	VkWriteDescriptorSet wr[3];
	for (int i = 0; i < 3; ++i) {
		dbi[i] = (VkDescriptorBufferInfo){ .buffer = buf[i], .offset = 0, .range = VK_WHOLE_SIZE };
		wr[i] = (VkWriteDescriptorSet){ .sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET, .dstSet = ds, .dstBinding = i,
			.descriptorCount = 1, .descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER, .pBufferInfo = &dbi[i] };
	}
	vkUpdateDescriptorSets(dev, 3, wr, 0, NULL);

	VkCommandPoolCreateInfo cpi = { .sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO, .queueFamilyIndex = family };
	VkCommandPool cp;
	CHECK(vkCreateCommandPool(dev, &cpi, NULL, &cp));
	VkCommandBufferAllocateInfo cbai = { .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO, .commandPool = cp,
		.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY, .commandBufferCount = 1 };
	VkCommandBuffer cb;
	CHECK(vkAllocateCommandBuffers(dev, &cbai, &cb));
	VkCommandBufferBeginInfo cbbi = { .sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
	CHECK(vkBeginCommandBuffer(cb, &cbbi));
	uint32_t push[12] = { 0 };
	vkCmdBindPipeline(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pipe);
	vkCmdBindDescriptorSets(cb, VK_PIPELINE_BIND_POINT_COMPUTE, pl, 0, 1, &ds, 0, NULL);
	vkCmdPushConstants(cb, pl, VK_SHADER_STAGE_COMPUTE_BIT, 0, sizeof push, push);
	vkCmdDispatch(cb, 1, 1, 1);
	CHECK(vkEndCommandBuffer(cb));

	VkFenceCreateInfo fci = { .sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO };
	VkFence fence;
	CHECK(vkCreateFence(dev, &fci, NULL, &fence));
	VkSubmitInfo si = { .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO, .commandBufferCount = 1, .pCommandBuffers = &cb };
	CHECK(vkQueueSubmit(queue, 1, &si, fence));
	CHECK(vkWaitForFences(dev, 1, &fence, VK_TRUE, 10ull * 1000 * 1000 * 1000));

	int bad = 0;
	for (int i = 0; i < N; ++i)
		if (map[2][i] != map[0][i] + map[1][i]) {
			if (bad++ < 4) printf("  MAL c[%d] = %g, esperado %g\n", i, map[2][i], map[0][i] + map[1][i]);
		}
	printf("%s: %d/%d correctos  (c[0]=%g c[1]=%g c[63]=%g)\n", bad ? "RESULTADO INCORRECTO" : "OK", N - bad, N, map[2][0], map[2][1], map[2][63]);
	return bad != 0;
}
